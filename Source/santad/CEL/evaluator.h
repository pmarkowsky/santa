/// Copyright 2023 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__SANTAD__CELEVALUATOR_EVALUATOR_H
#define SANTA__SANTAD__CELEVALUATOR_EVALUATOR_H

#include <stdint.h>

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace santa::santad::cel {

// Values to populate in the CEL Activation record used by the .
struct Context {
  uint64_t timestamp;
  // Args and Env Vars
  
};

class Evaluator {
 public:
  absl::StatusOr<bool> Evaluate(const std::string program, Context ctx);
  // TODO add an LRU cache of programs and methods for invalidating the cache.
};

}  // namespace santa::santad::celevaluator

#endif
