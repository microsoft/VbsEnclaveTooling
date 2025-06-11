// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <string>
#include <memory>
#include <type_traits>
#include <stdexcept>
#undef min
#undef max
#include <algorithm>

// All types and functions within this file should be usable within both the hostApp and the enclave.
namespace VbsEnclaveABI::Shared::Converters
{
    // Base for all generated struct metadata.
    template <typename T>
    struct StructMetadata;

    // Type traits
    template<typename T>
    struct is_unique_ptr : std::false_type {};

    template<typename T, typename D>
    struct is_unique_ptr<std::unique_ptr<T, D>> : std::true_type {};

    template<typename T>
    struct unique_ptr_inner_type { using type = void; };

    template<typename T, typename D>
    struct unique_ptr_inner_type<std::unique_ptr<T, D>> { using type = std::decay_t<T>; };

    template<typename T>
    using unique_ptr_inner_type_t = unique_ptr_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_unique_ptr_v = is_unique_ptr<std::decay_t<T>>::value;

    template <typename T>
    struct is_optional : std::false_type {};

    template <typename T>
    struct is_optional<std::optional<T>> : std::true_type {};

    template <typename T>
    struct optional_inner_type { using type = void; };

    template <typename T>
    struct optional_inner_type<std::optional<T>> { using type = std::decay_t<T>; };

    template<typename T>
    using optional_inner_type_t = optional_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_optional_v = is_optional<std::decay_t<T>>::value;

    template <typename T>
    struct is_vector : std::false_type {};

    template <typename T, typename Alloc>
    struct is_vector<std::vector<T, Alloc>> : std::true_type {};

    template <typename T>
    struct vector_inner_type { using type = void; };

    template <typename T, typename Alloc>
    struct vector_inner_type<std::vector<T, Alloc>> { using type = std::decay_t<T>; };

    template<typename T>
    using vector_inner_type_t = vector_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_vector_v = is_vector<T>::value;

    template <typename T>
    struct is_std_array : std::false_type {};

    template <typename T, std::size_t N>
    struct is_std_array<std::array<T, N>> : std::true_type {};

    template <typename T>
    struct std_array_inner_type { using type = void; };

    template <typename T, std::size_t N>
    struct std_array_inner_type<std::array<T, N>> { using type = std::decay_t<T>; };

    template<typename T>
    using std_array_inner_type_t = std_array_inner_type<std::decay_t<T>>::type;

    template <typename T>
    struct is_container_type : std::false_type {};

    template <>
    struct is_container_type<std::string> : std::true_type {};

    template <>
    struct is_container_type<std::wstring> : std::true_type {};

    template <typename U, typename Alloc>
    struct is_container_type<std::vector<U, Alloc>> : std::true_type {};

    template <typename U, std::size_t N>
    struct is_container_type<std::array<U, N>> : std::true_type {};

    template <typename T>
    constexpr bool is_container_v = is_container_type<T>::value;

    template <typename T>
    constexpr bool is_std_array_v = is_std_array<T>::value;

    template <typename T>
    using remove_pointer_t = typename std::remove_pointer<T>::type;

    template <typename T>
    struct vector_or_array_inner_type
    {
        static_assert(
            std::is_same_v<T, void>,
            "vector_or_array_inner_type<T>: T must be std::vector or std::array"
        );
    };

    template <typename T, typename Alloc>
    struct vector_or_array_inner_type<std::vector<T, Alloc>> { using type = std::decay_t<T>; };

    template <typename T, std::size_t N>
    struct vector_or_array_inner_type<std::array<T, N>> { using type = std::decay_t<T>; };

    template <typename T>
    using vector_or_array_inner_type_t = vector_or_array_inner_type<std::decay_t<T>>::type;

    template<typename T>
    concept UniquePtr = is_unique_ptr_v<T>;

    template<typename T>
    concept Optional = is_optional_v<T>;

    template<typename T>
    concept Vector = is_vector_v<T>;

    template<typename T>
    concept StdArray = is_std_array_v<T>;

    template<typename T>
    concept Container = is_container_v<T>;

    template<typename T>
    concept RawPtr = std::is_pointer_v<T>;

    template<typename T>
    concept NonWrappedStruct =
        std::is_class_v<std::decay_t<T>> &&    // Must be a class or struct
        !UniquePtr<std::decay_t<T>> &&   // Must not be unique ptr
        !Optional<std::decay_t<T>> && // Must not be optional
        !Container<std::decay_t<T>>; // Must not be wstring, string, vector or array

    template <typename T>
    concept IsRawPtrAndNonWrappedStruct = RawPtr<T> && NonWrappedStruct<remove_pointer_t<T>>;

    template <typename T>
    concept IsRawPtrAndNotNonWrappedStruct = RawPtr<T> && !NonWrappedStruct<remove_pointer_t<T>>;

    template <typename T, typename U>
    concept IsVectorAndStdArray = (Vector<T> && StdArray<U>) || (Vector<U> && StdArray<T>);

    template <typename T, typename U>
    concept AreBothUniquePtrs = UniquePtr<T> && UniquePtr<U>;

    template <typename T, typename U>
    concept AreBothArithmeticTypes = std::is_arithmetic_v<T> && std::is_arithmetic_v<U>;

    template <typename T, typename U>
    concept AreBothEnums = std::is_enum_v<T> && std::is_enum_v<U>;

    template <typename T, typename U>
    concept AreBothTheSame = std::is_same_v<T, U>;

    template <typename T, typename U>
    concept AreBothNonWrappedStructs = NonWrappedStruct<T> && NonWrappedStruct<U>;

    template <typename T, typename U>
    concept AreBothVectors = Vector<T> && Vector<U>;

    // Used only for static_asserts
    template<typename...> struct always_false : std::false_type {};

    template <
        template<typename...> class Wrapper,
        typename TargetInnerType,
        typename Src,
        typename ConvertFunc
    >
    auto ConvertToWrapper(const Src& src, ConvertFunc&& conversion_func)
    {
        using DecayedSrc = std::decay_t<Src>;

        if constexpr (UniquePtr<DecayedSrc> || RawPtr<DecayedSrc> || Optional<DecayedSrc>)
        {
            if (!src)
            {
                return Wrapper<TargetInnerType>{};
            }

            return conversion_func(*src);
        }
        else if constexpr (NonWrappedStruct<DecayedSrc>)
        {
            return conversion_func(src);
        }
        else
        {
            static_assert(always_false<Src>::value, "Unsupported src type for ConvertToWrapper.");
        }
    }

    template <UniquePtr Target, typename Src>
    inline std::decay_t<Target> ConvertToUniquePtr(const Src& src)
    {
        using TargetInnerType = unique_ptr_inner_type_t<Target>;

        auto conversion_func = [] (auto&& value)
        {
            using SrcInnerType = std::decay_t<decltype(value)>;
            auto ptr = std::make_unique<TargetInnerType>();
            *ptr = ConvertType<TargetInnerType>(value);
            return ptr;
        };

        return ConvertToWrapper<std::unique_ptr, TargetInnerType>(src, conversion_func);
    }

    template <Optional Target, typename Src>
    inline std::decay_t<Target> ConvertToOptional(const Src& src)
    {
        using TargetInnerType = optional_inner_type_t<Target>;

        auto conversion_func = [] (auto&& value)
        {
            using SrcInnerType = std::decay_t<decltype(value)>;
            return std::make_optional<TargetInnerType>(ConvertType<TargetInnerType>(value));
        };

        return ConvertToWrapper<std::optional, TargetInnerType>(src, conversion_func);
    }

    template<typename T>
    inline std::wstring ConvertToStdWString(const T& wstr)
    {
        if constexpr (UniquePtr<T>)
        {
            if (!wstr)
            {
                return {};
            }

            return std::wstring(wstr->wchars.begin(), wstr->wchars.end());
        }
        else
        {
            return std::wstring(wstr.wchars.begin(), wstr.wchars.end());
        }
    }

    template<typename Target>
    inline Target CreateWStringT(const std::wstring& wchars)
    {
        using DecayedType = std::decay_t<Target>;
        if constexpr (UniquePtr<DecayedType>)
        {
            using InnerType = unique_ptr_inner_type_t<DecayedType>;
            auto ptr = std::make_unique<InnerType>();
            ptr->wchars.assign(wchars.begin(), wchars.end());
            return ptr;
        }
        else if constexpr (NonWrappedStruct<DecayedType>)
        {
            DecayedType wcharT {};
            wcharT.wchars.assign(wchars.begin(), wchars.end());
            return wcharT;
        }
        else
        {
            static_assert(always_false<Target>::value, "CreateWStringT: Unsupported Target (must be unique_ptr or struct)");
        }
    }

    template <typename TargetVector, typename SrcContainer, typename ConvertFunc>
    TargetVector TransformVector(const SrcContainer& src, ConvertFunc&& conversion_func)
    {
        TargetVector target_vector;
        target_vector.reserve(src.size());
        for (const auto& value : src)
        {
            target_vector.emplace_back(conversion_func(value));
        }

        return target_vector;
    }

    template <typename StdArray, typename SrcVector, typename ConvertFunc>
    StdArray TransformVectorToStdArray(const SrcVector& src, ConvertFunc&& conversion_func)
    {
        StdArray array {};
        size_t N = std::min(array.size(), src.size());
        for (size_t i = 0; i < N; ++i)
        {
            array[i] = conversion_func(src[i]);
        }

        return array;
    }

    template <typename Target, typename Src>
    inline std::decay_t<Target> ConvertType(const Src& src)
    {
        using DecayedSrc = std::decay_t<Src>;
        using DecayedTarget = std::decay_t<Target>;

        if constexpr (AreBothTheSame<DecayedSrc, DecayedTarget>)
        {
            return src;
        }
        else if constexpr (AreBothArithmeticTypes<DecayedSrc, DecayedTarget>)
        {
            return src;
        }
        else if constexpr (AreBothNonWrappedStructs<DecayedSrc, DecayedTarget>)
        {
            return ConvertStruct<DecayedTarget>(src);
        }
        else if constexpr (AreBothEnums<DecayedSrc, DecayedTarget>)
        {
            return static_cast<DecayedTarget>(src);
        }
        // Convert WStringT flatbuffer src to std::wstring target. 
        else if constexpr (AreBothTheSame<DecayedTarget, std::wstring>)
        {
            // The Codegen will only pass std::wstring as a target when the source is related to WStringT.
            return ConvertToStdWString(src);
        }
        // Convert std::wstring source to WStringT flatbuffer target.
        else if constexpr (AreBothTheSame<DecayedSrc, std::wstring>) 
        {
            // The Codegen will only pass std::wstring as a source when the target is related to WStringT.
            return CreateWStringT<DecayedTarget>(src);
        }
        else if constexpr (AreBothUniquePtrs<DecayedSrc, DecayedTarget>)
        {
            return ConvertToUniquePtr<DecayedTarget>(src);
        }
        else if constexpr (UniquePtr<DecayedTarget> && Optional<DecayedSrc>)
        {
            return ConvertToUniquePtr<DecayedTarget>(src);
        }
        else if constexpr (UniquePtr<DecayedSrc> && NonWrappedStruct<DecayedTarget>)
        {
            if (!src)
            {
                return {};
            }

            using InnerSrcType = unique_ptr_inner_type_t<DecayedSrc>;
            return ConvertType<DecayedTarget>(*src);
        }
        else if constexpr (NonWrappedStruct<DecayedSrc> && UniquePtr<DecayedTarget>)
        {
            return ConvertToUniquePtr<DecayedTarget>(src);
        }
        else if constexpr (RawPtr<DecayedSrc> && UniquePtr<DecayedTarget>)
        {
            return ConvertToUniquePtr<DecayedTarget>(src);
        }
        else if constexpr (IsRawPtrAndNonWrappedStruct<DecayedSrc>)
        {
            return ConvertToUniquePtr<DecayedTarget>(src);
        }
        // pointers to primitive/enum dev types get converted to std::optional primitive/enum flatbuffers.
        else if constexpr (IsRawPtrAndNotNonWrappedStruct<DecayedSrc>)
        {
            return ConvertToOptional<DecayedTarget>(src);
        }
        else if constexpr (UniquePtr<DecayedSrc> && Optional<DecayedTarget>)
        {
            return ConvertToOptional<DecayedTarget>(src);
        }
        else if constexpr (AreBothVectors<DecayedSrc, DecayedTarget> || (StdArray<DecayedSrc> && Vector<DecayedTarget>))
        {
            using InnerSrcType = vector_or_array_inner_type_t<DecayedSrc>;
            using InnerTargetType = vector_or_array_inner_type_t<DecayedTarget>;
            return TransformVector<DecayedTarget>(src, [] (const InnerSrcType& value)
            {
                return ConvertType<InnerTargetType>(value);
            });
        }
        else if constexpr (Vector<DecayedSrc> && StdArray<DecayedTarget>)
        {
            using InnerSrcType = vector_inner_type_t<DecayedSrc>;
            using InnerTargetType = std_array_inner_type_t<DecayedTarget>;

            return TransformVectorToStdArray<DecayedTarget>(src, [] (const InnerSrcType& value)
            {
                return ConvertType<InnerTargetType>(value);
            });
        }
        else
        {
            static_assert(always_false<DecayedSrc, DecayedTarget>::value,
                "Conversion not found in function: " __FUNCSIG__);
        }
    }

    template <NonWrappedStruct Target, NonWrappedStruct Src>
    inline std::decay_t<Target> ConvertStruct(const Src& src)
    {
        using DecayedSrc = std::decay_t<decltype(src)>;
        using DecayedTarget = std::decay_t<Target>;

        constexpr size_t N = std::tuple_size_v<decltype(StructMetadata<DecayedSrc>::members)>;
        static_assert(N == std::tuple_size_v<decltype(StructMetadata<DecayedTarget>::members)>,
            "Source and Target structs must have the same number of fields!");
        
        DecayedTarget target_struct{};

        auto for_each_field = [&]<std::size_t... I>(std::index_sequence<I...>)
        {
            (
                (
                    [&]
                    {
                        auto& src_field = src.*(std::get<I>(StructMetadata<DecayedSrc>::members));
                        auto& dst_field = target_struct.*(std::get<I>(StructMetadata<DecayedTarget>::members));
                        using DecayedSrcFieldT = std::decay_t<decltype(src_field)>;
                        using DecayedTargetFieldT = std::decay_t<decltype(dst_field)>;

                        dst_field = ConvertType<DecayedTargetFieldT>(src_field);
                    }()
                ), ...
            );
        };

        for_each_field(std::make_index_sequence<N>{});

        return target_struct;
    }
}

