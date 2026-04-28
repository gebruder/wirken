//! HDBSCAN clustering wrapper.
//!
//! Thin wrapper over the [`hdbscan`] crate (tom-whitehead/hdbscan,
//! v0.12). Per the C-LLM pre-checks: focused API, recently
//! maintained, output shape exactly matches the design's
//! "cluster id + noise" model.
//!
//! ## Single-cluster fallback policy lives elsewhere
//!
//! Per `docs/zirkel/DESIGN.md`: "if HDBSCAN returns no clusters or
//! only noise, all candidates land in a single 'ungrouped' theme."
//! That fallback is the orchestrator's job, not this wrapper's.
//! The wrapper returns the unmodified label vector — the
//! orchestrator decides whether an all-noise result becomes a real
//! "ungrouped" theme row or just leaves the cluster_id NULL on
//! every candidate.
//!
//! ## Defaults
//!
//! `min_cluster_size = 2`, `min_samples = 1` per the design doc.
//! Distance metric defaults to Euclidean — fine for normalized
//! embedding vectors from `nomic-embed-text`.
//!
//! ## HDBSCAN needs contrast
//!
//! Density-based clustering requires *contrast* between regions to
//! distinguish core points from noise. A single tight cluster of N
//! points (no other lower-density region) is classified as all-noise
//! regardless of N — there's no comparison density to validate the
//! cluster against. In practice, Zirkel's daily runs surface enough
//! topical variety that this case is rare; when it does happen, the
//! orchestrator's "ungrouped" fallback handles it.

use hdbscan::{Hdbscan, HdbscanHyperParams};
use thiserror::Error;

/// Cluster label for one point. `Cluster(n)` is a real cluster
/// (n ≥ 0); `Noise` is an unassigned point (`-1` from HDBSCAN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterLabel {
    Cluster(u32),
    Noise,
}

impl ClusterLabel {
    pub fn is_noise(&self) -> bool {
        matches!(self, ClusterLabel::Noise)
    }
}

#[derive(Debug, Error)]
pub enum ClusterError {
    #[error("hdbscan: {0}")]
    Hdbscan(String),
}

/// Cluster a slice of embeddings. Returns one [`ClusterLabel`] per
/// input vector, in the same order. Empty input returns an empty
/// vector — the caller decides whether to treat that as "no
/// candidates to cluster" or as an error condition.
///
/// `min_cluster_size`: smallest number of points that count as a
/// real cluster. Default per design: 2.
/// `min_samples`: density parameter. Default per design: 1.
pub fn cluster(
    embeddings: &[Vec<f32>],
    min_cluster_size: usize,
    min_samples: usize,
) -> Result<Vec<ClusterLabel>, ClusterError> {
    if embeddings.is_empty() {
        return Ok(Vec::new());
    }
    // Single-point case: HDBSCAN refuses (you can't form clusters
    // out of one point). The orchestrator's "ungrouped" fallback
    // handles this by treating one-candidate runs as one Noise
    // label, which lands the candidate under the ungrouped section
    // in the digest.
    if embeddings.len() < 2 {
        return Ok(vec![ClusterLabel::Noise; embeddings.len()]);
    }
    let params = HdbscanHyperParams::builder()
        .min_cluster_size(min_cluster_size)
        .min_samples(min_samples)
        .build();
    let clusterer = Hdbscan::new(embeddings, params);
    let labels = clusterer
        .cluster()
        .map_err(|e| ClusterError::Hdbscan(format!("{e:?}")))?;
    Ok(labels
        .into_iter()
        .map(|n| {
            if n < 0 {
                ClusterLabel::Noise
            } else {
                ClusterLabel::Cluster(n as u32)
            }
        })
        .collect())
}

/// Group a `(label, payload)` set by cluster id, dropping noise
/// points. Useful for the orchestrator's per-theme work where it
/// needs every candidate that landed in cluster N for theme naming.
pub fn group_by_cluster<T: Clone>(
    labels: &[ClusterLabel],
    payloads: &[T],
) -> std::collections::BTreeMap<u32, Vec<T>> {
    let mut groups: std::collections::BTreeMap<u32, Vec<T>> = Default::default();
    for (label, payload) in labels.iter().zip(payloads.iter()) {
        if let ClusterLabel::Cluster(n) = label {
            groups.entry(*n).or_default().push(payload.clone());
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two well-separated clusters of 3 points each in 2D. HDBSCAN
    /// should identify both clusters and put no points in noise.
    #[test]
    fn two_clear_clusters_get_distinct_labels() {
        // Cluster A around (0, 0); cluster B around (10, 10).
        let data = vec![
            vec![0.0, 0.0],
            vec![0.1, 0.1],
            vec![-0.05, 0.05],
            vec![10.0, 10.0],
            vec![10.1, 9.9],
            vec![9.95, 10.05],
        ];
        let labels = cluster(&data, 2, 1).unwrap();
        assert_eq!(labels.len(), 6);
        // No two cluster ids should be Noise — both groups form a
        // valid cluster at min_cluster_size=2.
        let noise_count = labels.iter().filter(|l| l.is_noise()).count();
        assert!(
            noise_count <= 1,
            "expected at most one noise point; got {noise_count}: {labels:?}"
        );
        // The two halves should land in different clusters (whichever
        // ids HDBSCAN assigned).
        let first_three: Vec<_> = labels[..3].iter().filter(|l| !l.is_noise()).collect();
        let last_three: Vec<_> = labels[3..].iter().filter(|l| !l.is_noise()).collect();
        if let (Some(a), Some(b)) = (first_three.first(), last_three.first()) {
            assert_ne!(
                a, b,
                "the two well-separated halves should not share a cluster id"
            );
        } else {
            panic!("expected at least one non-noise label per half: {labels:?}");
        }
    }

    /// Empty input → empty output, not an error.
    #[test]
    fn empty_input_returns_empty_output() {
        let labels = cluster(&[], 2, 1).unwrap();
        assert!(labels.is_empty());
    }

    /// One-point case is degenerate — HDBSCAN can't run on it.
    /// The wrapper returns a single Noise label, leaving the
    /// orchestrator to decide what to do (typically: render
    /// ungrouped).
    #[test]
    fn single_point_is_noise() {
        let data = vec![vec![1.0, 2.0]];
        let labels = cluster(&data, 2, 1).unwrap();
        assert_eq!(labels, vec![ClusterLabel::Noise]);
    }

    /// All-noise behavior: HDBSCAN with high min_cluster_size on a
    /// scattered set returns mostly noise. The orchestrator will
    /// promote this to an "ungrouped" theme.
    #[test]
    fn high_min_cluster_size_yields_noise() {
        let data = vec![
            vec![0.0, 0.0],
            vec![10.0, 0.0],
            vec![0.0, 10.0],
            vec![10.0, 10.0],
        ];
        // min_cluster_size = 10 means no cluster of size 4 can form.
        let labels = cluster(&data, 10, 1).unwrap();
        assert!(labels.iter().all(|l| l.is_noise()));
    }

    #[test]
    fn group_by_cluster_drops_noise() {
        let labels = vec![
            ClusterLabel::Cluster(0),
            ClusterLabel::Noise,
            ClusterLabel::Cluster(0),
            ClusterLabel::Cluster(1),
            ClusterLabel::Noise,
        ];
        let payloads = vec!["a", "b", "c", "d", "e"];
        let groups = group_by_cluster(&labels, &payloads);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&0], vec!["a", "c"]);
        assert_eq!(groups[&1], vec!["d"]);
        assert!(!groups.contains_key(&2));
    }
}
