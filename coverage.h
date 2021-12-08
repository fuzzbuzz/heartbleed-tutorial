#include <assert.h>
#include <v8.h>

#ifndef COVERAGE_H
#define COVERAGE_H

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::NewStringType;
using v8::Object;
using v8::String;
using v8::Value;

// comparisons bitmap
struct comparison_bitmap {
	static const size_t kMapSizeInBits = 1 << 16;
	static const size_t kMapPrimeMod =
	    65371; // Largest Prime < kMapSizeInBits;
	static const size_t kBitsInWord = (sizeof(uintptr_t) * 8);
	static const size_t kMapSizeInWords = kMapSizeInBits / kBitsInWord;

      public:
	// Clears all bits.
	void Reset() { memset(Map, 0, sizeof(Map)); }

	// Computes a hash function of Value and sets the corresponding bit.
	// Returns true if the bit was changed from 0 to 1.
	inline bool AddValue(uintptr_t Value)
	{
		uintptr_t Idx = Value % kMapSizeInBits;
		uintptr_t WordIdx = Idx / kBitsInWord;
		uintptr_t BitIdx = Idx % kBitsInWord;
		uintptr_t Old = Map[WordIdx];
		uintptr_t New = Old | (1ULL << BitIdx);
		Map[WordIdx] = New;
		return New != Old;
	}

	inline bool AddValueModPrime(uintptr_t Value)
	{
		return AddValue(Value % kMapPrimeMod);
	}

	inline bool Get(uintptr_t Idx)
	{
		assert(Idx < kMapSizeInBits);
		uintptr_t WordIdx = Idx / kBitsInWord;
		uintptr_t BitIdx = Idx % kBitsInWord;
		return Map[WordIdx] & (1ULL << BitIdx);
	}

	size_t SizeInBits() const { return kMapSizeInBits; }

	uintptr_t Map[kMapSizeInWords];
};

void Get8BitCounters(const FunctionCallbackInfo<Value> &args);

void Reset8BitCounters(const FunctionCallbackInfo<Value> &args);

void GetComparisonBitmap(const FunctionCallbackInfo<Value> &args);

#endif
