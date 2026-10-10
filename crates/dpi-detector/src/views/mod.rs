//! Human-readable report screens: one module per test, plus the banner and the
//! summary panel.

pub(crate) mod banner;
pub(crate) mod burst;
pub(crate) mod dns;
pub(crate) mod domains;
pub(crate) mod netinfo;
pub(crate) mod summary;
pub(crate) mod tcp;
pub(crate) mod telegram;
pub(crate) mod whitelist;

/// Groups values by a key, keeping the order the keys were first seen.
///
/// The order vector is load-bearing, not decoration: a `HashMap` yields its
/// keys in an order that depends on the hasher, so a table that iterates one
/// directly reorders its rows between runs. Two views group this way — the DNS
/// endpoint table and the netinfo panel's static resolvers — and each had its
/// own copy of the `contains_key`-then-push dance, which is the kind of
/// invariant a third copy gets wrong silently.
///
/// A view that only needs the map (the DNS availability table, whose row order
/// comes from `all_names`) does not belong here: `entry().or_default().push()`
/// says what it means.
pub(crate) fn group_in_order<K, V>(
    items: impl IntoIterator<Item = (K, V)>,
) -> (Vec<K>, std::collections::HashMap<K, Vec<V>>)
where
    K: Eq + std::hash::Hash + Clone,
{
    let mut order: Vec<K> = Vec::new();
    let mut by_key: std::collections::HashMap<K, Vec<V>> = std::collections::HashMap::new();
    for (key, value) in items {
        if !by_key.contains_key(&key) {
            order.push(key.clone());
        }
        by_key.entry(key).or_default().push(value);
    }
    (order, by_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The order is the one the keys were first seen in, not the map's.
    #[test]
    fn a_grouped_table_keeps_the_order_it_was_given() {
        let (order, by_key) = group_in_order([
            ("b", 1),
            ("a", 2),
            ("b", 3),
            ("c", 4),
            ("a", 5),
        ]);
        assert_eq!(order, vec!["b", "a", "c"]);
        assert_eq!(by_key["b"], vec![1, 3]);
        assert_eq!(by_key["a"], vec![2, 5]);
        assert_eq!(by_key["c"], vec![4]);
    }

    /// An empty input is an empty pair, not a panic.
    #[test]
    fn an_empty_input_groups_to_nothing() {
        let (order, by_key) = group_in_order(Vec::<(String, u8)>::new());
        assert!(order.is_empty() && by_key.is_empty());
    }
}
