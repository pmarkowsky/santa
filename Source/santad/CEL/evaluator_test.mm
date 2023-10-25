

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include "Source/santad/CELEvaluator/evaluator.h"
#include "absl/status/status.h"
#include <string>

using santa::santad::cel::Context;
using santa::santad::cel::Evaluator;

@interface SantaCELEvaluatorTest  : XCTestCase 
@end

@implementation SantaCELEvaluatorTest

- (void)testEvaluation {
    Evaluator cel_eval = Evaluator();
    std::string program = std::string("timestamp > 0");
    struct Context ctx = { .timestamp = 1 };
    absl::StatusOr<bool> result = cel_eval.Evaluate(program, ctx);
    XCTAssertEqual(result.value(), true);
    ctx.timestamp = 0;
    result = cel_eval.Evaluate(program, ctx);
    XCTAssertEqual(result.value(), false);
}

@end
