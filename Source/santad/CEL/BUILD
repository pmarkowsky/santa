load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

package(default_visibility = ["//:santa_package_group"], )

cc_library(name = "cel_evaluator",
hdrs = ["evaluator.h"],
srcs = ["evaluator.cc"],
copts = ["-Wno-unused-private-field"],
#cxxopts = ["-Wno-unused-private-field"],
deps = [ 
      "@com_google_absl//absl/status:status",
      "@com_google_cel_cpp//eval/public:activation",
      "@com_google_cel_cpp//eval/public:activation_bind_helper",
      "@com_google_cel_cpp//eval/public:cel_expr_builder_factory",
      "@com_google_cel_cpp//eval/public:builtin_func_registrar",
      "@com_google_cel_cpp//eval/public/structs:cel_proto_wrapper",
      "@com_google_cel_cpp//eval/public/containers:field_access",
      "@com_google_cel_cpp//parser",
      "@com_google_cel_cpp//eval/public:cel_expression",
      "@com_google_cel_cpp//eval/public:cel_options",
      "@com_google_cel_cpp//eval/public:cel_value",
      "@com_google_cel_cpp//extensions/protobuf:value",
      ]
)

santa_unit_test(
    name = "cel_evaluator_test",
    srcs = ["evaluator_test.mm"],
    copts = ["-Wno-unused-private-field", "-Wno-unused-variable"],
    deps = [":cel_evaluator",
            "@com_google_absl//absl/status:status",
            "@com_google_cel_cpp//eval/public:cel_expression",
            "@com_google_cel_cpp//eval/public:cel_options",
            "@com_google_cel_cpp//eval/public:cel_value",
            "@com_google_cel_cpp//base:value",
            "@com_google_cel_cpp//extensions/protobuf:value",
    ],
)
