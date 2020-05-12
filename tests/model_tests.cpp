/*
Copyright (c) 2020 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <cstring>
#include "catch2/catch.hpp"

#include <nf/model_support.h>

#define BAR_MODEL(xx, ...)\
xx(num, int, none, num, __VA_ARGS__)\
xx(nump, int, ptr, nump, __VA_ARGS__) \
xx(isOK, bool, none, ok, __VA_ARGS__)\
xx(msg, string, none, msg, __VA_ARGS__)\
xx(errors, string, array, errors, __VA_ARGS__)\
xx(codes, int, array, codes, __VA_ARGS__)

DECLARE_MODEL(Bar, BAR_MODEL)

IMPL_MODEL(Bar, BAR_MODEL)

#define FOO_MODEL(xx, ...) \
xx(bar, Bar, none, bar, __VA_ARGS__) \
xx(barp, Bar, ptr, barp, __VA_ARGS__) \
xx(bar_arr, Bar, array, bara, __VA_ARGS__)

DECLARE_MODEL(Foo, FOO_MODEL)

IMPL_MODEL(Foo, FOO_MODEL)

using namespace Catch::Matchers;

#define BAR1 "{\
\"num\":42,\
\"ok\": false,\
\"errors\": [\"error1\", \"error2\"], \
\"codes\": [401, 403] \
}"

static void checkBar1(const Bar &bar) {
    CHECK(bar.num == 42);
    CHECK(!bar.isOK);
    CHECK_THAT(bar.errors[0], Equals("error1"));
    CHECK_THAT(bar.errors[1], Equals("error2"));
    CHECK(bar.errors[2] == nullptr);

    int c1 = *bar.codes[0];
    CHECK(c1 == 401);
    int c2 = *bar.codes[1];
    CHECK(c2 == 403);
    CHECK(bar.codes[2] == nullptr);
}

#define BAR2 "{\
\"num\":-42,\
\"ok\": true,\
}"

static void checkBar2(const Bar &bar) {
    CHECK(bar.num == -42);
    CHECK(bar.isOK);
    CHECK(bar.errors == nullptr);
    CHECK(bar.codes == nullptr);
}

TEST_CASE("new model tests") {
    const char *bar_json = BAR1;
    Bar bar;

    REQUIRE(parse_Bar(&bar, bar_json, strlen(bar_json)) == 0);

    checkBar1(bar);

    free_Bar(&bar);
}

TEST_CASE("embedded struct") {
    const char *json = "{"
                       "\"bar\":" BAR1 ","
                       "\"barp\": " BAR2 ","
                       "\"bara\": [" BAR1 "," BAR2 "]"
                       "}";
    Foo foo;
    REQUIRE(parse_Foo(&foo, json, strlen(json)) == 0);
    checkBar1(foo.bar);

    REQUIRE(foo.barp != nullptr);
    checkBar2(*foo.barp);

    REQUIRE(foo.bar_arr != nullptr);
    CHECK(foo.bar_arr[2] == nullptr);
    checkBar1(*foo.bar_arr[0]);
    checkBar2(*foo.bar_arr[1]);

    free_Foo(&foo);
}

TEST_CASE("test skipped fields") {
    const char *json = R"({
        "bar":{
            "num":42,
            "ok":true,
            "msg":"hello world!"
        },
        "skipper": [{"this":"should be skipped"},42,null],
        "also-skip": {"more":"skipping"},
        "barp":{
            "skip-field":{},
            "nump":42,
            "ok":true,
            "msg":"hello world!"
        }
    })";
    Foo foo;
    REQUIRE(parse_Foo(&foo, json, strlen(json)) == 0);

    REQUIRE(foo.bar.num == 42);
    REQUIRE(foo.bar.isOK);
    REQUIRE_THAT(foo.bar.msg, Catch::Matchers::Equals("hello world!"));

    REQUIRE(foo.barp != nullptr);
    REQUIRE(*foo.barp->nump == 42);
    REQUIRE(foo.barp->isOK);
    REQUIRE_THAT(foo.barp->msg, Catch::Matchers::Equals("hello world!"));
    free_Foo(&foo);
}

TEST_CASE("test string escape", "[model]") {
    const char *json = R"({
        "msg":"\thello\n\"world\"!"
    })";

    Bar bar;
    REQUIRE(parse_Bar(&bar, json, strlen(json)) == 0);
    REQUIRE_THAT(bar.msg, Equals("\thello\n\"world\"!"));
}

#define baz_model(XX, ...) \
XX(bar, json, none, bar, __VA_ARGS__) \
XX(ok, bool, none, ok, __VA_ARGS__)

#define MODEL_API static
DECLARE_MODEL(Baz, baz_model)
IMPL_MODEL(Baz, baz_model)

TEST_CASE("test raw json", "[model]") {
    const char *json = "{"
                       "\"bar\":" BAR1 ","
                       "\"ok\": true"
                       "}";
    Baz baz;
    REQUIRE(parse_Baz(&baz, json, strlen(json)) == 0);
    REQUIRE_THAT(baz.bar, Equals(BAR1));
    REQUIRE(baz.ok);

    Bar bar;
    REQUIRE(parse_Bar(&bar, baz.bar, strlen(baz.bar)) == 0);
    checkBar1(bar);
    free_Bar(&bar);
    free_Baz(&baz);
}

#define map_model(XX, ...) \
XX(map, model_map, none, map, __VA_ARGS__) \
XX(ok, bool, none, ok, __VA_ARGS__)

DECLARE_MODEL(ObjMap, map_model)
IMPL_MODEL(ObjMap, map_model)

TEST_CASE("model map test", "[model]") {
    const char *json = "{"
                       "\"map\":" BAR1 ","
                       "\"ok\": true"
                       "}";

    ObjMap o;
    REQUIRE(parse_ObjMap(&o, json, strlen(json)) == 0);
    CHECK(o.ok);
    CHECK_THAT((const char *) model_map_get(&o.map, "num"), Equals("42"));
    CHECK_THAT((const char *) model_map_get(&o.map, "errors"), Equals(R"(["error1", "error2"])"));

    model_map_clear(&o.map, nullptr);
}

TEST_CASE("model compare", "[model]") {
    Bar b1 = {
            .num = 45,
            .isOK = false,
            .msg = "this is bar1"
    };

    Bar b2 = {
            .num = 42,
            .isOK = true,
            .msg = "this is bar2"

    };

    CHECK(model_cmp(&b1, &b2, &Bar_META) != 0);

    b1.isOK = true;
    CHECK(model_cmp(&b1, &b2, &Bar_META) != 0);

    b2.num = 45;
    b2.msg = "this is bar1";
    CHECK(model_cmp(&b1, &b2, &Bar_META) == 0);
}

TEST_CASE("model compare with map", "[model]") {

    ObjMap o1 = {.ok = true};
    ObjMap o2 = {.ok = true};

    CHECK(cmp_ObjMap(&o1, &o2) == 0);

    model_map_set(&o1.map, "key1", (void *) "one");
    CHECK(cmp_ObjMap(&o1, &o2) != 0);

    model_map_set(&o2.map, "key2", (void *) "two");
    CHECK(cmp_ObjMap(&o1, &o2) != 0);

    model_map_set(&o2.map, "key1", (void *) "one");
    model_map_set(&o1.map, "key2", (void *) "two");
    CHECK(cmp_ObjMap(&o1, &o2) == 0);

}