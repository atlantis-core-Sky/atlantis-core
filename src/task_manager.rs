use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatus {
    pub id: String,
    pub task_type: String,
    pub status: String, // "pending", "running", "completed", "failed"
    pub result: Option<String>,
    pub error: Option<String>,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
}

impl TaskStatus {
    pub fn new(task_type: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            task_type: task_type.to_string(),
            status: "pending".to_string(),
            result: None,
            error: None,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            started_at: None,
            completed_at: None,
        }
    }
}

pub struct TaskManager {
    tasks: Arc<Mutex<HashMap<String, TaskStatus>>>,
    max_tasks: usize,
}

impl TaskManager {
    pub fn new(max_tasks: usize) -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            max_tasks,
        }
    }

    pub fn create_task(&self, task_type: &str) -> Result<String, String> {
        let mut tasks = self.tasks.lock().unwrap();
        
        if tasks.len() >= self.max_tasks {
            let to_remove: Vec<String> = tasks
                .iter()
                .filter(|(_, t)| t.status == "completed" || t.status == "failed")
                .map(|(id, _)| id.clone())
                .take(50)
                .collect();
            
            for id in to_remove {
                tasks.remove(&id);
            }
        }
        
        let task = TaskStatus::new(task_type);
        let task_id = task.id.clone();
        tasks.insert(task_id.clone(), task);
        
        Ok(task_id)
    }

    pub fn start_task(&self, task_id: &str) -> bool {
        let mut tasks = self.tasks.lock().unwrap();
        if let Some(task) = tasks.get_mut(task_id) {
            if task.status == "pending" {
                task.status = "running".to_string();
                task.started_at = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                );
                return true;
            }
        }
        false
    }

    pub fn complete_task(&self, task_id: &str, result: String) -> bool {
        let mut tasks = self.tasks.lock().unwrap();
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = "completed".to_string();
            task.result = Some(result);
            task.completed_at = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
            return true;
        }
        false
    }

    pub fn fail_task(&self, task_id: &str, error: String) -> bool {
        let mut tasks = self.tasks.lock().unwrap();
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = "failed".to_string();
            task.error = Some(error);
            task.completed_at = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
            return true;
        }
        false
    }

    pub fn get_task(&self, task_id: &str) -> Option<TaskStatus> {
        let tasks = self.tasks.lock().unwrap();
        tasks.get(task_id).cloned()
    }

    pub fn get_all_tasks(&self) -> Vec<TaskStatus> {
        let tasks = self.tasks.lock().unwrap();
        tasks.values().cloned().collect()
    }

    pub fn cleanup_old_tasks(&self, max_age_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|_, task| {
            if task.status == "completed" || task.status == "failed" {
                if let Some(completed_at) = task.completed_at {
                    return now - completed_at < max_age_secs;
                }
            }
            true
        });
    }
}
