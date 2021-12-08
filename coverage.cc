#include "coverage.h"
#include <v8.h>

#include <assert.h>
#include <cstring>
#include <stdio.h>

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::NewStringType;
using v8::Object;
using v8::String;
using v8::Value;

#undef COVERAGE_8BIT_DEBUG

class Cov8BitCounterTracker
{
      private:
	std::vector<std::pair<char *, char *>> _counters;

	size_t _bufferSize = 0;
	bool _needNewBuffer = false;
	v8::Persistent<v8::ArrayBuffer> _buffer;

      public:
	static Cov8BitCounterTracker &instance()
	{
		static Cov8BitCounterTracker t;
		return t;
	}

	void addCoverage(char *start, char *end)
	{
		_needNewBuffer = true;
		_bufferSize += end - start;

		fprintf(stderr,
			"8bit counter init %p -> %p (%lu), total buffer"
			"size is %lu\n",
			start, end, end - start, _bufferSize);

		_counters.push_back(std::make_pair(start, end));
	}

	void get(const FunctionCallbackInfo<Value> &args)
	{
		v8::Isolate *isolate = args.GetIsolate();
		v8::EscapableHandleScope handle_scope(isolate);

		v8::Local<v8::ArrayBuffer> array;

		if (_needNewBuffer) {
#ifdef COVERAGE_8BIT_DEBUG
			fprintf(stderr, "creating a new buffer of %lu\n",
				_bufferSize);
#endif

			array = v8::ArrayBuffer::New(isolate, _bufferSize);
			_buffer.Reset(isolate, array);
			_needNewBuffer = false;
		} else {
			array = _buffer.Get(isolate);
		}

		if (array.IsEmpty()) {
			// XXX - Error
			return;
		}

		uint8_t *p, *q;

#if V8_MAJOR_VERSION < 8
		p = static_cast<uint8_t *>(array->GetContents().Data());
#else
		p = static_cast<uint8_t *>(array->GetBackingStore()->Data());
#endif

#ifdef COVERAGE_8BIT_DEBUG
		fprintf(stderr, "array buffer contents is %p\n", p);
#endif

		q = p;
		for (const auto &range : _counters) {
			size_t count = range.second - range.first;

#ifdef COVERAGE_8BIT_DEBUG
			fprintf(stderr, "copying %p -> %p (%lu) to %p\n",
				range.first, range.second, count, q);
#endif
			memcpy(q, range.first, count);
			q += count;
		}

		v8::Local<v8::Uint8Array> byteArray =
		    v8::Uint8Array::New(array, 0, array->ByteLength());

		if (byteArray.IsEmpty()) {
			// XXX - Error
			return;
		}

		args.GetReturnValue().Set(handle_scope.Escape(byteArray));
	}

	void reset(const FunctionCallbackInfo<Value> &args)
	{
		for (const auto &range : _counters) {
			size_t count = range.second - range.first;
			std::memset(static_cast<void *>(range.first), 0, count);
		}

		if (_buffer.IsEmpty()) {
			return;
		}

		v8::Isolate *isolate = args.GetIsolate();
		v8::HandleScope hs(isolate);
		v8::Local<v8::ArrayBuffer> array = _buffer.Get(isolate);

		void *p;
#if V8_MAJOR_VERSION < 8
		p = static_cast<uint8_t *>(array->GetContents().Data());
#else
		p = static_cast<uint8_t *>(array->GetBackingStore()->Data());
#endif

		std::memset(p, 0, array->ByteLength());
	}
};

extern "C" void __sanitizer_cov_8bit_counters_init(char *start, char *end)
{
	Cov8BitCounterTracker::instance().addCoverage(start, end);
}

void Get8BitCounters(const FunctionCallbackInfo<Value> &args)
{
	Cov8BitCounterTracker::instance().get(args);
}

void Reset8BitCounters(const FunctionCallbackInfo<Value> &args)
{
	Cov8BitCounterTracker::instance().reset(args);
}

comparison_bitmap _comparison_ctx;

void GetComparisonBitmap(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

	void *buf = (void *)_comparison_ctx.Map;
	size_t nbuf = _comparison_ctx.kMapSizeInBits / 8;

#if V8_MAJOR_VERSION < 8
	v8::Local<v8::ArrayBuffer> array =
	    v8::ArrayBuffer::New(isolate, buf, nbuf);
#else
	// See the note above regarding backing stores, and the garbage
	// collector.
	std::unique_ptr<v8::BackingStore> store =
	    v8::ArrayBuffer::NewBackingStore(
		buf, nbuf, v8::BackingStore::EmptyDeleter, nullptr);

	v8::Local<v8::ArrayBuffer> array =
	    v8::ArrayBuffer::New(isolate, std::move(store));
#endif

	if (array.IsEmpty()) {
		// XXX - Error
		return;
	}

	v8::Local<v8::Uint8Array> byteArray =
	    v8::Uint8Array::New(array, 0, nbuf);

	if (byteArray.IsEmpty()) {
		// XXX - Error
		return;
	}

	args.GetReturnValue().Set(handle_scope.Escape(byteArray));
}

thread_local uintptr_t __sancov_lowest_stack;

extern "C" void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
					 const uintptr_t *pcs_end)
{
	// [pcs_beg,pcs_end) is the array of ptr-sized integers representing
	// pairs [PC,PCFlags] for every instrumented block in the current DSO.
	// Capture this array in order to read the PCs and their Flags.
	// The number of PCs and PCFlags for a given DSO is the same as the
	// number of 8-bit counters (-fsanitize-coverage=inline-8bit-counters),
	// or boolean flags (-fsanitize-coverage=inline=bool-flags), or
	// trace_pc_guard callbacks (-fsanitize-coverage=trace-pc-guard). A
	// PCFlags describes the basic block:
	//  * bit0: 1 if the block is the function entry block, 0 otherwise.
}

extern "C" void __sanitizer_cov_trace_pc_indir(int *pc)
{
	// Stub to allow linking with code built with
	// -fsanitize=indirect-calls,trace-pc.
	// This isn't used currently.
}

// comparisons bitmap
/*typedef struct comparison_bitmap {
    static const size_t kMapSizeInBits = 1 << 16;
    static const size_t kMapPrimeMod = 65371;  // Largest Prime <
kMapSizeInBits; static const size_t kBitsInWord = (sizeof(uintptr_t) * 8);
    static const size_t kMapSizeInWords = kMapSizeInBits / kBitsInWord;

  public:

    // Clears all bits.
    void Reset() { memset(Map, 0, sizeof(Map)); }

    // Computes a hash function of Value and sets the corresponding bit.
    // Returns true if the bit was changed from 0 to 1.
    inline bool AddValue(uintptr_t Value) {
	uintptr_t Idx = Value % kMapSizeInBits;
	uintptr_t WordIdx = Idx / kBitsInWord;
	uintptr_t BitIdx = Idx % kBitsInWord;
	uintptr_t Old = Map[WordIdx];
	uintptr_t New = Old | (1ULL << BitIdx);
	Map[WordIdx] = New;
	return New != Old;
    }

    inline bool AddValueModPrime(uintptr_t Value) {
	return AddValue(Value % kMapPrimeMod);
    }

    inline bool Get(uintptr_t Idx) {
	assert(Idx < kMapSizeInBits);
	uintptr_t WordIdx = Idx / kBitsInWord;
	uintptr_t BitIdx = Idx % kBitsInWord;
	return Map[WordIdx] & (1ULL << BitIdx);
    }

    size_t SizeInBits() const { return kMapSizeInBits; }

  private:
    // TODO this should be properly aligned
    static uintptr_t Map[kMapSizeInWords];
} comparison_bitmap;*/

template <class T> void handleComparison(uintptr_t pc, T arg1, T arg2)
{
	uint64_t argXor = arg1 ^ arg2;
	uint64_t hammingDistance = __builtin_popcount(argXor);
	uint64_t absoluteDistance =
	    (arg1 == arg2 ? 0 : __builtin_clzll(arg1 - arg2) + 1);

	_comparison_ctx.AddValue((pc * 128) + hammingDistance);
	_comparison_ctx.AddValue((pc * 128) + 64 + absoluteDistance);
	_comparison_ctx.AddValue(0);
}

extern "C" void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	handleComparison(pc, Arg1, Arg2);
}

extern "C" void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	handleComparison(pc, Arg1, Arg2);
}

extern "C" void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	handleComparison(pc, Arg1, Arg2);
}

extern "C" void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	handleComparison(pc, Arg1, Arg2);
}

extern "C" void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	handleComparison(pc, Arg1, Arg2);
}

extern "C" void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	handleComparison(pc, Arg1, Arg2);
}

extern "C" void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	handleComparison(pc, Arg1, Arg2);
}

extern "C" void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2)
{
	uintptr_t pc = (uintptr_t)__builtin_return_address(0);
	handleComparison(pc, Arg1, Arg2);
}

extern "C" void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases) {}
