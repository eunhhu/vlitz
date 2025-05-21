// src/gum/store.rs

use crate::util::lengthed;
use super::vzdata::VzData;
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
            self.data.insert(to, data);
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
        let new_page = current_page_num.saturating_add(count) - 1;
        println!("new_page_idx: {} {}", new_page, max_page_num);
        let new_cursor = new_page
            .min(max_page_num - 1)
            .max(0)
            .saturating_mul(self.page_size);
        println!("new_cursor: {}", new_cursor);
        self.set_cursor(new_cursor);
    }

    pub fn prev_page(&mut self, count: usize) {
        let (current_page_num, max_page_num) = self.get_page_info();
        if current_page_num <= 1 {
            return;
        }
        let new_page = current_page_num.saturating_sub(count) - 1;
        let new_cursor = new_page
            .min(max_page_num - 1)
            .max(0)
            .saturating_mul(self.page_size);
        println!("new_cursor: {}", new_cursor);
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
                lengthed(&global_idx.to_string(), max_idx_len).blue(),
                item
            ));
        }
        format!("{}{}", header, body)
    }

    // pub fn sort(&mut self, sort_by: &str) {
    //     self.data.sort_by_key(|item| item);
    //     self.adjust_cursor();
    // }
}