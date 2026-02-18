// Copyright 2026 ObsidianBox Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Result wrapper for JSON output

use serde::Serialize;
use chrono::Utc;

#[derive(Serialize)]
pub struct NativeResult<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub timestamp: i64,
}

impl<T: Serialize> NativeResult<T> {
    pub fn success(data: T) -> String {
        let result = NativeResult {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now().timestamp(),
        };
        serde_json::to_string(&result).unwrap_or_else(|_| error_result("Serialization failed"))
    }
    
    pub fn error(msg: &str) -> String {
        error_result(msg)
    }
}

pub fn error_result(msg: &str) -> String {
    #[derive(Serialize)]
    struct ErrorResult {
        success: bool,
        error: String,
        timestamp: i64,
    }
    
    let result = ErrorResult {
        success: false,
        error: msg.to_string(),
        timestamp: Utc::now().timestamp(),
    };
    serde_json::to_string(&result).unwrap_or_else(|_| {
        r#"{"success":false,"error":"Critical serialization error","timestamp":0}"#.to_string()
    })
}
