#include "evaluator.h"

#include "eval/public/activation.h"
#include "eval/public/activation_bind_helper.h"
#include "eval/public/builtin_func_registrar.h"
#include "eval/public/cel_expr_builder_factory.h"
#include "eval/public/containers/container_backed_list_impl.h"
#include "eval/public/containers/container_backed_map_impl.h"
#include "eval/public/containers/field_access.h"
#include "eval/public/structs/cel_proto_wrapper.h"
#include "parser/parser.h"

namespace santa::santad::cel {
namespace cel_parser = google::api::expr::parser;
namespace cel_runtime = google::api::expr::runtime;

// used for both protobuf and the CEL runtime.
using namespace google;

absl::StatusOr<bool> santa::santad::cel::Evaluator::Evaluate(
    const std::string program, struct santa::santad::cel::Context ctx) {
  auto parse_status = cel_parser::Parse(program);

  if (!parse_status.ok()) {
    return parse_status.status();
  }

  // retrieve the parsed expression.
  auto parsed_expr = parse_status.value();

  protobuf::Arena arena;

  // Register default functions
  cel_runtime::InterpreterOptions options;
  auto builder = cel_runtime::CreateCelExpressionBuilder(options);
  auto status = cel_runtime::RegisterBuiltinFunctions(builder->GetRegistry());

  if (!status.ok()) {
    return status;
  }

  google::api::expr::v1alpha1::SourceInfo source_info;

  auto cel_expression_status =
      builder->CreateExpression(&parsed_expr.expr(), &source_info);
  if (!cel_expression_status.ok()) {
    return cel_expression_status.status();
  }

  auto cel_expr = std::move(cel_expression_status.value());

  cel_runtime::Activation activation;

  activation.InsertValue("timestamp",
                         cel_runtime::CelValue::CreateUint64(ctx.timestamp));

  auto eval_status = cel_expr->Evaluate(activation, &arena);

  cel_runtime::CelValue result = eval_status.value();

  // Return the status error if we encountred an error during evaluation.
  if (result.IsError()) {
    return result.ErrorOrDie();
  }

  // Return the result of the evaluation.
  if (!result.IsBool()) {
    return absl::Status(absl::StatusCode::kInternal, "Result is not a boolean");
  }

  return result.BoolOrDie();
}
}  // namespace santa::santad::cel