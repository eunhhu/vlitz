// src/gum/store.rs

use crate::util::lengthed;
use super::{filter::{FilterSegment, FilterValue, FilterOperator, LogicalOperator}, vzdata::{VzData, VzDataType}};
use std::fmt::Debug; // Required for format!("{:?}") on VzDataType
use crossterm::style::Stylize;
use std::{collections::BTreeSet, fmt};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SelectorType {
    Indices(Vec<usize>),
    All,
}

impl fmt::Display for SelectorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectorType::Indices(indices) => write!(f, "{}", indices.iter().map(|i| i.to_string()).collect::<Vec<String>>().join(" ")),
            SelectorType::All => write!(f, "all"),
        }
    }
}


pub struct Store {
    pub name: String,
    pub data: Vec<VzData>,
    pub cursor: usize,
    pub page_size: usize,
}

impl Store {
    pub fn new(name: String) -> Self {
        Store {
            name,
            data: Vec::new(),
            cursor: 0,
            page_size: 50,
        }
    }

    fn adjust_cursor(&mut self) {
        let total_data_len = self.data.len();

        if total_data_len == 0 {
            self.cursor = 0;
            return;
        }

        if self.page_size == 0 {
            self.cursor = 0;
            return;
        }

        self.cursor = (self.cursor / self.page_size).saturating_mul(self.page_size);
    }

    pub fn add_data(&mut self, data: VzData) {
        self.data.push(data);
    }

    pub fn add_datas(&mut self, datas: Vec<VzData>) {
        self.data.extend(datas);
    }

    pub fn remove_data(&mut self, index: usize, count: usize) {
        if index < self.data.len() {
            let end = (index + count).min(self.data.len());
            self.data.drain(index..end);
            self.adjust_cursor();
        }
    }

    pub fn move_data(&mut self, from: usize, to: usize) {
        if from < self.data.len() {
            let data = self.data.remove(from);
            self.data.insert(to.min(self.data.len()), data);
        }
    }

    pub fn clear_data(&mut self) {
        self.data.clear();
        self.adjust_cursor();
    }

    pub fn get_current_data(&self) -> &[VzData] {
        let start_index = self.cursor;
        let end_index = (self.cursor + self.page_size).min(self.data.len());

        &self.data[start_index..end_index]
    }

    pub fn get_data_by_page(&self, page: usize) -> Result<Vec<&VzData>, String> {
        let (_, total_pages) = self.get_page_info();
        let page_idx = page.max(1).min(total_pages) - 1;
        let start_index = page_idx.saturating_mul(self.page_size);
        let end_index = (page_idx + 1).min(total_pages).saturating_mul(self.page_size);
        self.get_data_by_range(start_index, end_index)
    }

    pub fn get_data_at(&self, index: usize) -> Result<&VzData, String> {
        if index < self.data.len() {
            Ok(&self.data[index])
        } else {
            Err("Index out of bounds".to_string())
        }
    }

    pub fn get_data_by_range(&self, start: usize, end: usize) -> Result<Vec<&VzData>, String> {
        let start_index = start.min(self.data.len());
        let end_index = end.min(self.data.len());
        if start_index > end_index || end_index > self.data.len() {
            return Err("Invalid range".to_string());
        }
        Ok(self.data[start_index..end_index].iter().collect())
    }

    pub fn get_multiple_data(&self, indices: &[usize]) -> Result<Vec<&VzData>, String> {
        let mut result = Vec::new();
        for &index in indices {
            if index < self.data.len() {
                result.push(&self.data[index]);
            } else {
                return Err(format!("Index {} out of bounds", index));
            }
        }
        Ok(result)
    }

    pub fn get_all_data(&self) -> Result<Vec<&VzData>, String> {
        if self.data.is_empty() {
            return Err("No data available".to_string());
        }
        Ok(self.data.iter().collect())
    }

    pub fn get_cursor(&self) -> usize {
        self.cursor
    }

    pub fn get_cursor_end(&self) -> usize {
        if self.data.is_empty() {
            return 0;
        }
        let end_index = (self.cursor + self.page_size - 1).min(self.data.len() - 1);
        end_index
    }

    pub fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
        self.adjust_cursor();
    }

    pub fn next_page(&mut self, count: usize) {
        let (current_page_num, max_page_num) = self.get_page_info();

        if current_page_num >= max_page_num {
            return;
        }
        let new_page = (current_page_num.saturating_add(count)).min(max_page_num) - 1;
        let new_cursor = new_page
            .min(max_page_num - 1)
            .max(0)
            .saturating_mul(self.page_size);
        self.set_cursor(new_cursor);
    }

    pub fn prev_page(&mut self, count: usize) {
        let (current_page_num, max_page_num) = self.get_page_info();
        if current_page_num <= 1 {
            return;
        }
        let new_page = (current_page_num.saturating_sub(count)).max(1) - 1;
        let new_cursor = new_page
            .min(max_page_num - 1)
            .max(0)
            .saturating_mul(self.page_size);
        self.set_cursor(new_cursor);
    }

    pub fn get_page_info(&self) -> (usize, usize) {
        if self.data.is_empty() {
            return (1, 1);
        }
        if self.page_size == 0 {
            return (0, 0);
        }
        let current_page_num = (self.cursor as f64 / self.page_size as f64).ceil() as usize + 1;
        let total_pages = (self.data.len() as f64 / self.page_size as f64).ceil() as usize;
        (current_page_num, total_pages)
    }

    fn parse_selection_type(s: &str) -> Result<SelectorType, String> {
        if s == "all" {
            return Ok(SelectorType::All);
        }
        let mut indices = BTreeSet::new();
        for s in s.split(',').map(|s| s.trim()) {
            if s.is_empty() {
                continue;
            }
            if let Ok(index) = s.parse::<usize>() {
                indices.insert(index);
            } else {
                let ranges: Vec<_> = s.split('-').map(|s| s.trim()).collect();
                if ranges.len() > 2 {
                    return Err(format!("Invalid range: {}", s));
                } else {
                    let start = ranges.get(0).unwrap_or(&"0").parse::<usize>().unwrap_or(0);
                    let end = ranges.get(1).unwrap_or(&"0").parse::<usize>().unwrap_or(0);
                    if start > end {
                        return Err(format!("Invalid range: {}", s));
                    }
                    for i in start..=end {
                        indices.insert(i);
                    }
                }
            }
        }
        Ok(SelectorType::Indices(indices.into_iter().collect()))
    }

    pub fn get_data_by_selection(&self, selector: &str) -> Result<Vec<&VzData>, String> {
        if self.data.is_empty() {
            return Err("Store is empty".to_string());
        }
        let selector_type = Store::parse_selection_type(selector);
        match selector_type {
            Ok(selector_type) => {
                match selector_type {
                    SelectorType::Indices(indices) => self.get_multiple_data(&indices),
                    SelectorType::All => self.get_all_data(),
                }
            },
            Err(e) => Err(e),
        }
    }

    pub fn sort(&mut self, sort_by: Option<&str>) {
        self.data.sort_by_key(|item| match sort_by {
            Some("addr") => {
                match item {
                    VzData::Pointer(p) => p.address.to_string(),
                    VzData::Module(m) => m.address.to_string(),
                    VzData::Range(r) => r.address.to_string(),
                    VzData::Function(f) => f.address.to_string(),
                    VzData::Variable(v) => v.address.to_string(),
                    VzData::JavaClass(c) => c.name.to_string(),
                    VzData::JavaMethod(m) => m.name.to_string(),
                    VzData::ObjCClass(c) => c.name.to_string(),
                    VzData::ObjCMethod(m) => m.name.to_string(),
                    VzData::Thread(t) => t.id.to_string(),
                    _ => "".to_string(),
                }
            },
            _ | None => {
                match item {
                    VzData::Pointer(p) => p.address.to_string(),
                    VzData::Module(m) => m.name.to_string(),
                    VzData::Range(r) => r.address.to_string(),
                    VzData::Function(f) => f.name.to_string(),
                    VzData::Variable(v) => v.name.to_string(),
                    VzData::JavaClass(c) => c.name.to_string(),
                    VzData::JavaMethod(m) => m.name.to_string(),
                    VzData::ObjCClass(c) => c.name.to_string(),
                    VzData::ObjCMethod(m) => m.name.to_string(),
                    VzData::Thread(f) => f.id.to_string(),
                    _ => "".to_string(),
                }
            },
        });
        self.adjust_cursor();
    }

    pub fn filter(&mut self, filter_segments: Vec<FilterSegment>) {
        if filter_segments.is_empty() {
            return; // No filter, do nothing
        }

        let mut data = self.data.clone();
        data.retain(|item: &VzData| {
            filter_segments.iter().all(|segment| {
                match segment {
                    FilterSegment::Condition(cond) => self.evaluate_condition_for_item(item, cond),
                    FilterSegment::Logical(op) => match op {
                        LogicalOperator::And => true,
                        LogicalOperator::Or => false,
                    },
                }
            })
        });
        self.data = data;
        self.adjust_cursor();
    }

    fn evaluate_condition_for_item(&self, vz_data_item: &VzData, condition: &super::filter::FilterCondition) -> bool {
        if let Some(item_field_value) = self.get_field_value_for_filtering(vz_data_item, &condition.key) {
            return self.compare_filter_values(&item_field_value, &condition.operator, &condition.value);
        }
        false
    }

    fn get_field_value_for_filtering(&self, vz_data_item: &VzData, key: &str) -> Option<FilterValue> {
        match key.to_lowercase().as_str() {
            "name" => match vz_data_item {
                VzData::Module(m) => Some(FilterValue::String(m.name.clone())),
                VzData::Function(f) => Some(FilterValue::String(f.name.clone())),
                VzData::Variable(v) => Some(FilterValue::String(v.name.clone())),
                VzData::JavaClass(jc) => Some(FilterValue::String(jc.name.clone())),
                VzData::JavaMethod(jm) => Some(FilterValue::String(jm.name.clone())),
                VzData::ObjCClass(oc) => Some(FilterValue::String(oc.name.clone())),
                VzData::ObjCMethod(om) => Some(FilterValue::String(om.name.clone())),
                _ => None,
            },
            "address" => match vz_data_item {
                VzData::Pointer(p) => Some(FilterValue::Number(p.address as f64)),
                VzData::Module(m) => Some(FilterValue::Number(m.address as f64)),
                VzData::Range(r) => Some(FilterValue::Number(r.address as f64)),
                VzData::Function(f) => Some(FilterValue::Number(f.address as f64)),
                VzData::Variable(v) => Some(FilterValue::Number(v.address as f64)),
                _ => None,
            },
            "size" => match vz_data_item {
                VzData::Module(m) => Some(FilterValue::Number(m.size as f64)),    // Assumes m.size is a newtype like Size(u64)
                VzData::Range(r) => Some(FilterValue::Number(r.size as f64)),      // Assumes r.size is a newtype like Size(u64)
                _ => None,
            },
            "protect" | "protection" => match vz_data_item {
                VzData::Range(r) => Some(FilterValue::String(r.protection.clone())),
                _ => None,
            },
            "type" => match vz_data_item {
                VzData::Pointer(p) => Some(FilterValue::String(format!("{:?}", p.base.data_type).to_lowercase())),
                VzData::Module(m) => Some(FilterValue::String(format!("{:?}", m.base.data_type).to_lowercase())),
                VzData::Range(r) => Some(FilterValue::String(format!("{:?}", r.base.data_type).to_lowercase())),
                VzData::Function(f) => Some(FilterValue::String(format!("{:?}", f.base.data_type).to_lowercase())),
                VzData::Variable(v) => Some(FilterValue::String(format!("{:?}", v.base.data_type).to_lowercase())),
                VzData::JavaClass(jc) => Some(FilterValue::String(format!("{:?}", jc.base.data_type).to_lowercase())),
                VzData::JavaMethod(jm) => Some(FilterValue::String(format!("{:?}", jm.base.data_type).to_lowercase())),
                VzData::ObjCClass(oc) => Some(FilterValue::String(format!("{:?}", oc.base.data_type).to_lowercase())),
                VzData::ObjCMethod(om) => Some(FilterValue::String(format!("{:?}", om.base.data_type).to_lowercase())),
                VzData::Thread(t) => Some(FilterValue::String(format!("{:?}", t.base.data_type).to_lowercase())),
                _ => None,
            },
            "value_type" => match vz_data_item {
                VzData::Pointer(p) => Some(FilterValue::String(format!("{:?}", p.value_type).to_lowercase())),
                _ => None,
            },
            "id" => match vz_data_item {
                VzData::Thread(t) => Some(FilterValue::Number(t.id as f64)),
                _ => None,
            },
            "module" | "module_name" => match vz_data_item {
                VzData::Function(f) => Some(FilterValue::String(f.module.clone())),
                VzData::Variable(v) => Some(FilterValue::String(v.module.clone())),
                _ => None,
            },
            "class" | "class_name" => match vz_data_item {
                VzData::JavaMethod(jm) => Some(FilterValue::String(jm.class.clone())),
                VzData::ObjCMethod(om) => Some(FilterValue::String(om.class.clone())),
                _ => None,
            },
            _ => None,
        }
    }

    fn compare_filter_values(
        &self,
        item_val: &FilterValue,
        op: &super::filter::FilterOperator,
        filter_val: &FilterValue,
    ) -> bool {
        match (item_val, filter_val) {
            (FilterValue::String(s_item), FilterValue::String(s_filter)) => match op {
                FilterOperator::Equal => s_item.eq_ignore_ascii_case(s_filter),
                FilterOperator::NotEqual => !s_item.eq_ignore_ascii_case(s_filter),
                FilterOperator::Contains => s_item.to_lowercase().contains(&s_filter.to_lowercase()),
                FilterOperator::NotContains => !s_item.to_lowercase().contains(&s_filter.to_lowercase()),
                FilterOperator::LessThan => s_item < s_filter,
                FilterOperator::LessEqual => s_item <= s_filter,
                FilterOperator::GreaterThan => s_item > s_filter,
                FilterOperator::GreaterEqual => s_item >= s_filter,
            },
            (FilterValue::Number(n_item), FilterValue::Number(n_filter)) => match op {
                FilterOperator::Equal => (n_item - n_filter).abs() < f64::EPSILON,
                FilterOperator::NotEqual => (n_item - n_filter).abs() >= f64::EPSILON,
                FilterOperator::LessThan => n_item < n_filter,
                FilterOperator::LessEqual => n_item <= n_filter,
                FilterOperator::GreaterThan => n_item > n_filter,
                FilterOperator::GreaterEqual => n_item >= n_filter,
                _ => false,
            },
            (FilterValue::Bool(b_item), FilterValue::Bool(b_filter)) => match op {
                FilterOperator::Equal => b_item == b_filter,
                FilterOperator::NotEqual => b_item != b_filter,
                _ => false,
            },
            (FilterValue::Number(n_item), FilterValue::String(s_filter)) => {
                if let Ok(n_filter) = s_filter.parse::<f64>() {
                    self.compare_filter_values(&FilterValue::Number(*n_item), op, &FilterValue::Number(n_filter))
                } else { false }
            }
            (FilterValue::String(s_item), FilterValue::Number(n_filter)) => {
                if let Ok(n_item) = s_item.parse::<f64>() {
                    self.compare_filter_values(&FilterValue::Number(n_item), op, &FilterValue::Number(*n_filter))
                } else { false }
            }
            _ => false,
        }
    }

    
    pub fn to_string(&self, page: Option<usize>) -> String {
        let cursor = if self.data.len() > 0 {
            self.get_cursor()
        } else {
            0
        };
        let (current_page, total_pages) = self.get_page_info();
        let header = format!("{} {}-{} [{}] ({}/{})",
            self.name.clone().green(),
            cursor,
            self.get_cursor_end(),
            self.data.len().to_string().yellow(),
            current_page,
            total_pages
        );
        let data = self.get_data_by_page(page.unwrap_or(current_page)).unwrap();
        let max_idx_len = self.data.len().to_string().len();
        let mut body = String::new();
        for (i, item) in data.iter().enumerate() {
            let global_idx = self.get_cursor() + i;
            body.push_str(&format!("\n[{}] {}",
                format!("{:^width$}", global_idx, width = max_idx_len).blue(),
                item
            ));
        }
        format!("{}{}", header, body)
    }

}