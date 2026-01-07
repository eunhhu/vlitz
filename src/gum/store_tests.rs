// Tests for store.rs filtering and data management

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_pagination() {
        let mut store = Store::new("Test".into());

        // Add 150 items
        for i in 0..150 {
            store.add_datas(vec![VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: format!("module_{}", i),
                address: i as u64 * 0x1000,
                size: 0x1000,
            })]);
        }

        // Test page size (50 items per page)
        assert_eq!(store.data.len(), 150);
        let (current, total) = store.get_page_info();
        assert_eq!(current, 1);
        assert_eq!(total, 3);

        // Next page
        store.next_page(1);
        let (current, total) = store.get_page_info();
        assert_eq!(current, 2);

        // Last page
        store.set_cursor(100);
        let (current, total) = store.get_page_info();
        assert_eq!(current, 3);
    }

    #[test]
    fn test_parse_selection_all() {
        let mut store = Store::new("Test".into());
        store.add_datas(vec![VzData::Module(crate::gum::vzdata::VzModule {
            base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
            name: "test".into(),
            address: 0x1000,
            size: 0x1000,
        })]);

        let result = store.get_data_by_selection("all");
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.len(), 1);
    }

    #[test]
    fn test_parse_selection_indices() {
        let mut store = Store::new("Test".into());

        // Add 5 items
        for i in 0..5 {
            store.add_datas(vec![VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: format!("module_{}", i),
                address: i as u64 * 0x1000,
                size: 0x1000,
            })]);
        }

        // Test single index
        let result = store.get_data_by_selection("0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);

        // Test multiple indices
        let result = store.get_data_by_selection("0,2,4");
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.len(), 3);
    }

    #[test]
    fn test_parse_selection_range() {
        let mut store = Store::new("Test".into());

        // Add 5 items
        for i in 0..5 {
            store.add_datas(vec![VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: format!("module_{}", i),
                address: i as u64 * 0x1000,
                size: 0x1000,
            })]);
        }

        // Test range
        let result = store.get_data_by_selection("0-2");
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.len(), 3);

        // Test range with open end
        let result = store.get_data_by_selection("1-3");
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.len(), 3);
    }

    #[test]
    fn test_parse_selection_invalid() {
        let mut store = Store::new("Test".into());
        store.add_datas(vec![VzData::Module(crate::gum::vzdata::VzModule {
            base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
            name: "test".into(),
            address: 0x1000,
            size: 0x1000,
        })]);

        // Test invalid range (end before start)
        let result = store.get_data_by_selection("3-1");
        assert!(result.is_err());

        // Test invalid index (out of bounds)
        let result = store.get_data_by_selection("10");
        assert!(result.is_err());
    }

    #[test]
    fn test_sort_by_address() {
        let mut store = Store::new("Test".into());
        store.add_datas(vec![
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "c".into(),
                address: 0x3000,
                size: 0x1000,
            }),
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "a".into(),
                address: 0x1000,
                size: 0x2000,
            }),
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "b".into(),
                address: 0x2000,
                size: 0x3000,
            }),
        ]);

        // Sort by address
        store.sort(Some("addr"));

        // Verify order
        let current_data = store.get_current_data();
        assert_eq!(current_data.len(), 3);

        if let VzData::Module(r#mod) = &current_data[0] {
            assert_eq!(mod.address, 0x1000);
        }
        if let VzData::Module(r#mod) = &current_data[1] {
            assert_eq!(mod.address, 0x2000);
        }
        if let VzData::Module(r#mod) = &current_data[2] {
            assert_eq!(mod.address, 0x3000);
        }
    }

    #[test]
    fn test_filter_by_name() {
        let mut store = Store::new("Test".into());
        store.add_datas(vec![
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "test_module".into(),
                address: 0x1000,
                size: 0x1000,
            }),
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "other_module".into(),
                address: 0x2000,
                size: 0x2000,
            }),
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "sample".into(),
                address: 0x3000,
                size: 0x3000,
            }),
        ]);

        // Filter by name containing "test"
        store.filter(vec![crate::gum::filter::FilterSegment::Condition(
            crate::gum::filter::FilterCondition {
                key: "name".into(),
                operator: crate::gum::filter::FilterOperator::Contains,
                value: crate::gum::filter::FilterValue::String("test".into()),
            },
        )]);

        // Should only have "test_module"
        assert_eq!(store.data.len(), 1);
        assert_eq!(store.data.len(), 1);
    }

    #[test]
    fn test_filter_by_address() {
        let mut store = Store::new("Test".into());
        store.add_datas(vec![
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "module_1".into(),
                address: 0x1000,
                size: 0x1000,
            }),
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "module_2".into(),
                address: 0x2000,
                size: 0x2000,
            }),
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "module_3".into(),
                address: 0x3000,
                size: 0x3000,
            }),
        ]);

        // Filter by address >= 0x2000
        store.filter(vec![crate::gum::filter::FilterSegment::Condition(
            crate::gum::filter::FilterCondition {
                key: "address".into(),
                operator: crate::gum::filter::FilterOperator::GreaterEqual,
                value: crate::gum::filter::FilterValue::Number((0x2000 as u64).into()),
            },
        )]);

        // Should have module_2 and module_3
        assert_eq!(store.data.len(), 2);
    }

    #[test]
    fn test_move_data() {
        let mut store = Store::new("Test".into());
        store.add_datas(vec![
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "first".into(),
                address: 0x1000,
                size: 0x1000,
            }),
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "second".into(),
                address: 0x2000,
                size: 0x2000,
            }),
            VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: "third".into(),
                address: 0x3000,
                size: 0x3000,
            }),
        ]);

        // Move second to end (should go to last position)
        let result = store.move_data(1, 2);
        assert!(result.is_ok());

        // Verify order: first, third, second
        let current_data = store.get_current_data();
        assert_eq!(current_data.len(), 3);

        if let VzData::Module(r#mod) = &current_data[0] {
            assert_eq!(mod.name, "first");
        }
        if let VzData::Module(r#mod) = &current_data[1] {
            assert_eq!(mod.name, "third");
        }
        if let VzData::Module(r#mod) = &current_data[2] {
            assert_eq!(mod.name, "second");
        }
    }

    #[test]
    fn test_remove_data() {
        let mut store = Store::new("Test".into());

        // Add 5 items
        for i in 0..5 {
            store.add_datas(vec![VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: format!("module_{}", i),
                address: i as u64 * 0x1000,
                size: 0x1000,
            })]);
        }

        assert_eq!(store.data.len(), 5);

        // Remove items 1 and 2
        let result = store.remove_data(1, 2);
        assert!(result.is_ok());
        assert_eq!(store.data.len(), 3);

        // Verify remaining items are 0, 3, 4
        let current_data = store.get_current_data();
        if let VzData::Module(r#mod) = &current_data[0] {
            assert_eq!(mod.name, "module_0");
        }
        if let VzData::Module(r#mod) = &current_data[1] {
            assert_eq!(mod.name, "module_3");
        }
        if let VzData::Module(r#mod) = &current_data[2] {
            assert_eq!(mod.name, "module_4");
        }
    }

    #[test]
    fn test_clear_data() {
        let mut store = Store::new("Test".into());

        // Add 5 items
        for i in 0..5 {
            store.add_datas(vec![VzData::Module(crate::gum::vzdata::VzModule {
                base: crate::gum::vzdata::new_base(crate::gum::vzdata::VzDataType::Module),
                name: format!("module_{}", i),
                address: i as u64 * 0x1000,
                size: 0x1000,
            })]);
        }

        assert_eq!(store.data.len(), 5);

        // Clear all data
        store.clear_data();
        assert_eq!(store.data.len(), 0);
        assert_eq!(store.get_page_info(), (1, 1));
    }
}
