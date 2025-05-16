use crossterm::style::Stylize;

// src/gum/store.rs
use super::vzdata::VzData;

pub struct Store {
    pub data: Vec<VzData>,
    pub cursor: usize,
    pub page_size: usize,
}

impl Store {
    pub fn new() -> Self {
        Store {
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

        let last_page_start_index = total_data_len.saturating_sub(self.page_size);

        if self.cursor > last_page_start_index {
            self.cursor = last_page_start_index;
        }

        self.cursor = (self.cursor / self.page_size) * self.page_size;
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

    pub fn clear_data(&mut self) {
        self.data.clear();
        self.adjust_cursor();
    }

    pub fn get_current_data(&self) -> &[VzData] {
        let start_index = self.cursor;
        let end_index = (self.cursor + self.page_size).min(self.data.len());

        &self.data[start_index..end_index]
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
        let end_index = (self.cursor + self.page_size).min(self.data.len());
        end_index
    }

    pub fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
        self.adjust_cursor();
    }

    pub fn next_page(&mut self, count: usize) {
        let current_page_num = self.cursor / self.page_size;

        let new_cursor = (current_page_num + count) * self.page_size;

        if self.data.is_empty() || self.page_size == 0 {
            self.cursor = 0;
            return;
        }

        let last_page_start_index = self.data.len().saturating_sub(self.page_size);
        
        if new_cursor > last_page_start_index {
            self.cursor = last_page_start_index;
        } else {
            self.cursor = new_cursor;
        }
    }

    pub fn prev_page(&mut self, count: usize) {
        let current_page_num = self.cursor / self.page_size;

        if self.data.is_empty() || self.page_size == 0 {
            self.cursor = 0;
            return;
        }

        let new_cursor = current_page_num.saturating_sub(count) * self.page_size;
        self.cursor = new_cursor;
    }

    pub fn get_page_info(&self) -> (usize, usize) {
        if self.data.is_empty() || self.page_size == 0 {
            return (0, 0);
        }
        let current_page_num = (self.cursor / self.page_size) + 1;
        let total_pages = (self.data.len() as f64 / self.page_size as f64).ceil() as usize;
        (current_page_num, total_pages)
    }
}