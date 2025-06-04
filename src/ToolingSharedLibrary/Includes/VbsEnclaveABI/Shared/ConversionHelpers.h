// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <string>
#include <memory>
#include <type_traits>

// All types and functions within this file should be usable within both the hostApp and the enclave.
namespace VbsEnclaveABI::Shared::Convertors
{
    template <typename T>
    struct StructMetaData;

    // Helpers
    template <typename T>
    struct is_unique_ptr : std::false_type {};

    template <typename T>
    struct is_unique_ptr<std::unique_ptr<T>> : std::true_type {};

    template<typename T>
    struct unique_ptr_inner_type { using type = void; };

    template<typename T>
    struct unique_ptr_inner_type<std::unique_ptr<T>> { using type = T; };

    template <typename T>
    constexpr bool is_unique_ptr_v = is_unique_ptr<T>::value;

    template <typename T>
    struct is_std_optional : std::false_type {};

    template <typename U>
    struct is_std_optional<std::optional<U>> : std::true_type {};

    template <typename T>
    struct optional_inner_type { using type = void; };

    template <typename U>
    struct optional_inner_type<std::optional<U>> { using type = U; };

    template <typename T>
    constexpr bool is_std_optional_v = is_std_optional<T>::value;

    template <typename T>
    struct is_std_vector : std::false_type {};

    template <typename U, typename Alloc>
    struct is_std_vector<std::vector<U, Alloc>> : std::true_type {};

    template <typename T>
    struct std_vector_inner_type { using type = void; };

    template <typename U, typename Alloc>
    struct std_vector_inner_type<std::vector<U, Alloc>> { using type = U; };

    template <typename T>
    constexpr bool is_std_vector_v = is_std_vector<T>::value;

    template <typename T>
    struct is_std_array : std::false_type {};

    template <typename U, std::size_t N>
    struct is_std_array<std::array<U, N>> : std::true_type {};

    template <typename T>
    struct std_array_inner_type { using type = void; };

    template <typename U, std::size_t N>
    struct std_array_inner_type<std::array<U, N>> { using type = U; };

    template <typename T>
    constexpr bool is_std_array_v = is_std_array<T>::value;

    template <typename T>
    constexpr bool is_scalar_numeric_v = std::is_integral_v<T> || std::is_floating_point_v<T>;

    template <typename T>
    constexpr bool is_basic_supported_type_v = is_scalar_numeric_v<T> || std::is_same_v<std::decay_t<T>, std::string>;

    template <typename T>
    constexpr bool is_plain_struct_v =
        std::is_class_v<std::decay_t<T>> &&                // Must be a class or struct
        !is_unique_ptr<std::decay_t<T>>::value &&           // Not a unique_ptr
        !is_std_optional<std::decay_t<T>>::value;

    template <typename T>
    struct is_special_type : std::false_type {};

    template <>
    struct is_special_type<std::string> : std::true_type {};

    template <>
    struct is_special_type<std::wstring> : std::true_type {};

    template <typename U, typename Alloc>
    struct is_special_type<std::vector<U, Alloc>> : std::true_type {};

    template <typename U, std::size_t N>
    struct is_special_type<std::array<U, N>> : std::true_type {};

    template <
        typename FromType,
        typename ToType,
        std::enable_if_t<is_unique_ptr_v<FromType>, void>
    >
    inline ToType ConvertToUniquePtr(FromType& type)
    {
        if (!type)
        {
            return nullptr;
        }

        using FromInnerType = unique_ptr_inner_type<FromType>::type;
        using ToInnerType = unique_ptr_inner_type<ToType>::type;

        auto return_ptr = std::make_unique<ToInnerType>();

        *return_ptr = ConvertToDevType<FromInnerType, ToInnerType>(*type);
        return return_ptr;
    }

    template <
        typename FromType,
        typename ToType,
        std::enable_if_t<is_std_optional_v<FromType>, void>
    >
    inline ToType ConvertToUniquePtr(FromType& type)
    {
        if (!type)
        {
            return {};
        }

        using FromInnerType = optional_inner_type<FromType>::type;
        using ToInnerType = unique_ptr_inner_type<ToType>::type;

        auto return_ptr = std::make_unique<ToInnerType>();

        *return_ptr = ConvertToDevType<FromInnerType, ToInnerType>(type.value());
        return return_ptr;
    }

    enum class ConversionType
    {
        ToDevType,
        ToFlatbuffer
    };

    template <typename From, typename To>
    void ConvertStruct(const From& from, To& to, ConversionType conversion_type);

    template <
        typename FromType,
        typename ToType,
        std::enable_if_t<is_unique_ptr_v<FromType>, void>
    >
    inline ToType UniquePtrToPlainStruct(FromType& from_type)
    {
        THROW_HR_IF_NULL(E_INVALIDARG, type.get());
        using FromInnerType = unique_ptr_inner_type<FromType>::type;
        ToType ret_type{};

        ConvertStruct<FromInnerType, ToType>(*from_type, ret_type, ConversionType::ToDevType);
        return ret_type;
    }

    template<typename T>
    inline std::wstring ConvertToStdWString(const T& wstr)
    {
        return std::wstring(wstr.wchars.begin(), wstr.wchars.end());
    }

    template<typename T>
    inline std::unique_ptr<T> CreateWStringT(const std::wstring& wchars)
    {
        auto wchar_ptr = std::make_unique<T>();
        THROW_IF_NULL_ALLOC(wchar_ptr);
        wchar_ptr->wchars.assign(wchars.begin(), wchars.end());
        return wchar_ptr;
    }
    template<typename T, typename U>
    inline U ConvertEnum(T enum_1)
    {
        return static_cast<U>(enum_1);
    }

    // Main processer
    template <typename FlatbufferType, typename DevType>
    inline DevType ConvertToDevType(FlatbufferType& flatbuffer_type)
    {
        using DecayedFlatbufferType = std::decay_t<FlatbufferType>;
        using DecayedDevType = std::decay_t<DevType>;

        if constexpr (is_basic_supported_type_v<DecayedFlatbufferType>)
        {
            return flatbuffer_type;
        }
        else if constexpr (std::is_same_v<DecayedDevType, std::wstring>)
        {
            return flatbuffer_type ? ConvertToStdWString(*flatbuffer_type) : {};
        }
        else if constexpr (is_unique_ptr<DecayedFlatbufferType>::value && is_unique_ptr<DecayedDevType>::value)
        {
            return ConvertToUniquePtr<DecayedFlatbufferType, DecayedDevType>(flatbuffer_type);
        }
        // Handle case where struct field in flatbuffer is std::optional but dev type is unique_ptr struct value
        else if constexpr (is_std_optional<DecayedFlatbufferType>::value && is_unique_ptr<DecayedDevType>::value)
        {
            return ConvertToUniquePtr<DecayedFlatbufferType, DecayedDevType>(flatbuffer_type);
        }
        // Handle case where struct field in flatbuffer is unique_ptr but dev type is normal struct value
        else if constexpr (is_unique_ptr<DecayedFlatbufferType>::value && is_plain_struct_v<DecayedDevType>::value)
        {
            return UniquePtrToPlainStruct<DecayedFlatbufferType, DecayedDevType>(flatbuffer_type);
        }
        else if constexpr (is_std_vector_v<DecayedFlatbufferType> && is_std_vector_v<DecayedDevType>::value)
        {
            DecayedDevType dev_type{};
            dev_type.reserve(flatbuffer_type.size());
            for (auto& value : flatbuffer_type)
            {
                dev_type.emplace_back(ConvertToDevType(value));
            }

            return dev_type;
        }
        else if constexpr (is_std_vector_v<DecayedFlatbufferType> && is_std_array_v<DecayedDevType>::value)
        {
            return flatbuffer_type;
        }

        throw std::runtime_error("No conversion function available for flatbuffer to dev type");
    }



    template <typename From, typename To, size_t... I>
    void ConvertStructImpl(const From& from, To& to, ConversionType conversion_type, std::index_sequence<I...>)
    {
        (
            (
                [&] {
                    auto& src_field = from.*(std::get<I>(StructMetaData<From>::members));
                    auto& dst_field = to.*(std::get<I>(StructMetaData<To>::members));
                    using SrcT = std::decay_t<decltype(src_field)>;
                    using DstT = std::decay_t<decltype(dst_field)>;
                    if constexpr (
                        std::is_class_v<SrcT> && 
                        std::is_class_v<DstT> &&
                        !is_special_type<SrcT> &&
                        !is_special_type<DstT>)
                    {
                        // Recursively convert nested struct fields, but not for std::string
                        ConvertStruct(src_field, dst_field, conversion_type);
                    }
                    else if (conversion_type == ConversionType::ToDevType)
                    {
                        dst_field = ConvertToDevType<decltype(src_field), decltype(dst_field)>(src_field);
                    }
                    else
                    {
                        dst_field = ConvertToDevType<decltype(src_field), decltype(dst_field)>(src_field);
                    }
                }()
            ), ...
        );
    }

    template <typename From, typename To>
    void ConvertStruct(const From& from, To& to, ConversionType conversion_type)
    {
        constexpr size_t N = StructMetaData<From>::count;
        static_assert(N == StructMetaData<To>::count, "Structs must have the same number of fields!");
        ConvertStructImpl<From, To>(from, to, conversion_type, std::make_index_sequence<N>{});
    }
}

