// hello.cc
#include <node.h>
#include <string>
#include <iostream>
#include <assert.h>

#include <stdio.h>
namespace fuzztarget {

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::NewStringType;
using v8::Object;
using v8::String;
using v8::Value;

static struct {
	char *cov_8bit_counters_start;
	char *cov_8bit_counters_end;
} _ctx = {
	0,
	0
};

extern "C"
void __sanitizer_cov_8bit_counters_init(char *start, char *end) {
	fprintf(stderr, "8bit counter init %p -> %p\n", start, end);
	_ctx.cov_8bit_counters_start = start;
	_ctx.cov_8bit_counters_end = end;
}

// Do some computations with 'str', return the result.
// This function contains a bug. Can you spot it?
size_t BrokenMethod(const std::string &str) {
	std::vector<int> Vec({0, 1, 2, 3, 4});
	size_t Idx = 0;
	if (str.size() > 5)
		Idx++;
	if (str.find("foo") != std::string::npos)
		Idx++;
	if (str.find("bar") != std::string::npos)
		Idx++;
	if (str.find("ouch") != std::string::npos)
		Idx++;
	if (str.find("omg") != std::string::npos)
		Idx++;

	assert(Idx < 5);

	return Vec[Idx];
}

std::string toString(v8::Isolate *isolate, v8::Local<Value> s) {
	std::string out;

	if (s->IsNullOrUndefined()) {
		out = "";
	} else if (s->IsArrayBufferView()) {
		v8::Local<v8::ArrayBufferView> view = v8::Local<v8::ArrayBufferView>::Cast(s);
		v8::Local<v8::ArrayBuffer> buf = view->Buffer();
		v8::ArrayBuffer::Contents c = buf->GetContents();

		out = std::string((const char *)c.Data(), c.ByteLength());
	} else {
		v8::String::Utf8Value str(isolate, s);
		out = *str;
	}

	return out;
}

void Method(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();

	auto ret = BrokenMethod(toString(isolate, args[0]));
	args.GetReturnValue().Set((int)ret);
}

void BrokenMethod2(const std::string &str) {
	if (str[0] != 'q') {return;}
	if (str[1] != 'w') {return;}
	if (str[2] != 'e') {return;}
	if (str[3] != 'r') {return;}
	if (str[4] != 't') {return;}
	if (str[5] != 'y') {return;}
	return;
}

void Method2(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();
	BrokenMethod2(toString(isolate, args[0]));
}

void Get8BitCounters(const FunctionCallbackInfo<Value>& args) {
	if (_ctx.cov_8bit_counters_start == nullptr || _ctx.cov_8bit_counters_end == nullptr) {
		return;
	}

	v8::Isolate* isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

	void *buf = _ctx.cov_8bit_counters_start;
	size_t nbuf = _ctx.cov_8bit_counters_end - _ctx.cov_8bit_counters_start;

	v8::Local<v8::ArrayBuffer> array = v8::ArrayBuffer::New(isolate, buf, nbuf);

	if (array.IsEmpty()) {
		// XXX - Error
		return;
	}

	v8::Local<v8::Uint8Array> byteArray = v8::Uint8Array::New(array, 0, nbuf);

	if (byteArray.IsEmpty()) {
		// XXX - Error
		return;
	}

	args.GetReturnValue().Set(handle_scope.Escape(byteArray));
}

void Reset8BitCounters(const FunctionCallbackInfo<Value>& args) {
	if (_ctx.cov_8bit_counters_start == nullptr || _ctx.cov_8bit_counters_end == nullptr) {
		return;
	}

	void *buf = _ctx.cov_8bit_counters_start;
	size_t nbuf = _ctx.cov_8bit_counters_end - _ctx.cov_8bit_counters_start;

	memset(buf, 0, nbuf);
}

void Initialize(Local<Object> exports, Local<Value> hey, void *you) {
	NODE_SET_METHOD(exports, "BrokenMethod", Method);
	NODE_SET_METHOD(exports, "Get8BitCounters", Get8BitCounters);
	NODE_SET_METHOD(exports, "Reset8BitCounters", Reset8BitCounters);
	NODE_SET_METHOD(exports, "BrokenMethod2", Method2);
}

NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)

}  // namespace demo
