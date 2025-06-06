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
namespace VbsEnclaveABI::Shared::Convertors
{
    template <typename T>
    struct StructMetaData;

    // Helpers
    template<typename T>
    struct is_unique_ptr : std::false_type {};

    template<typename T, typename D>
    struct is_unique_ptr<std::unique_ptr<T, D>> : std::true_type {};

    template<typename T>
    struct unique_ptr_inner_type { using type = void; };

    template<typename T, typename D>
    struct unique_ptr_inner_type<std::unique_ptr<T, D>> { using type = std::decay_t<T>; };

    template<typename T>
    using unique_ptr_inner_type_t = typename unique_ptr_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_unique_ptr_v = is_unique_ptr<std::decay_t<T>>::value;

    template <typename T>
    struct is_std_optional : std::false_type {};

    template <typename U>
    struct is_std_optional<std::optional<U>> : std::true_type {};

    template <typename T>
    struct optional_inner_type { using type = void; };

    template <typename U>
    struct optional_inner_type<std::optional<U>> { using type = std::decay_t<U>; };

    template <typename T>
    constexpr bool is_std_optional_v = is_std_optional<T>::value;

    template <typename T>
    struct is_std_vector : std::false_type {};

    template <typename U, typename Alloc>
    struct is_std_vector<std::vector<U, Alloc>> : std::true_type {};

    template <typename T>
    struct std_vector_inner_type { using type = void; };

    template <typename U, typename Alloc>
    struct std_vector_inner_type<std::vector<U, Alloc>> { using type = std::decay_t<U>; };

    template<typename T>
    using std_vector_inner_type_t = typename std_vector_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_std_vector_v = is_std_vector<T>::value;

    template <typename T>
    struct is_std_array : std::false_type {};

    template <typename U, std::size_t N>
    struct is_std_array<std::array<U, N>> : std::true_type {};

    template <typename T>
    struct std_array_inner_type { using type = void; };

    template <typename U, std::size_t N>
    struct std_array_inner_type<std::array<U, N>> { using type = std::decay_t<U>; };

    template<typename T>
    using std_array_inner_type_t = typename std_array_inner_type<std::decay_t<T>>::type;

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
    constexpr bool is_std_array_v = is_std_array<T>::value;

    template <typename T>
    constexpr bool is_scalar_numeric_v = std::is_integral_v<std::decay_t<T>> || std::is_floating_point_v<std::decay_t<T>>;

    template <typename T>
    constexpr bool is_plain_struct_v =
        std::is_class_v<std::decay_t<T>> &&         // Must be a class or struct
        !is_unique_ptr_v<std::decay_t<T>> &&   // Must not be unique ptr
        !is_std_optional_v<std::decay_t<T>> && // Must not be optional
        !is_container_type<std::decay_t<T>>::value; // Must not be wstring, string, vector or array

    enum class ConversionType
    {
        ToDevType,
        ToFlatbuffer
    };

    template <typename FromType, typename ToType>
    decltype(auto) ConvertToObj(const FromType& arg, ConversionType conversion_type)
    {
        if (conversion_type == ConversionType::ToDevType)
        {
            return ConvertToDevType<FromType, ToType>(arg);
        }

        return ConvertToFlatbuffer<FromType, ToType>(arg);
    }

    //template <typename FromType, typename ToType>
    //inline std::enable_if_t<is_unique_ptr_v<FromType> && is_plain_struct_v<ToType>, std::decay_t<ToType>>
    //ConvertFromUniquePtrToStruct(const FromType& from_type, ConversionType conversion_type)
    //{
    //    if (!from_type)
    //    {
    //        return {};
    //    }

    //    using FromInnerType = unique_ptr_inner_type_t<FromType>;
    //    ToType to_type{};
    //    ConvertStruct<FromInnerType, ToType>(*return_ptr, to_type, conversion_type);
    //    return to_type;
    //}

    template <typename FromType, typename ToType>
    inline std::enable_if_t<is_unique_ptr_v<FromType>, std::decay_t<ToType>>
    ConvertToUniquePtr(const FromType& from_type, ConversionType conversion_type)
    {
        if (!from_type)
        {
            return nullptr;
        }

        using FromInnerType = unique_ptr_inner_type_t<FromType>;
        using ToInnerType = unique_ptr_inner_type_t<ToType>;

        auto return_ptr = std::make_unique<ToInnerType>();
        THROW_HR_IF_NULL(E_INVALIDARG, return_ptr.get());
        *return_ptr = ConvertToObj<FromInnerType, ToInnerType>(*from_type, conversion_type);
        return return_ptr;
    }

    template <typename FromType, typename ToType>
    inline std::enable_if_t<std::is_pointer_v<FromType>, std::decay_t<ToType>>
    ConvertToUniquePtr(const FromType& from_type, ConversionType conversion_type)
    {
        if (!from_type)
        {
            return nullptr;
        }

        using FromInnerType = std::remove_pointer_t<std::decay_t<FromType>>;
        using ToInnerType = unique_ptr_inner_type_t<ToType>;
        auto return_ptr = std::make_unique<ToInnerType>();
        THROW_HR_IF_NULL(E_INVALIDARG, return_ptr.get());
        *return_ptr = ConvertToObj<FromInnerType, ToInnerType>(*from_type, conversion_type);
        return return_ptr;
    }

    template <typename FromType, typename ToType>
    inline std::enable_if_t<is_std_optional_v<FromType>, std::decay_t<ToType>>
        ConvertToUniquePtr(const FromType& from_type, ConversionType conversion_type)
    {
        if (!from_type)
        {
            return {};
        }

        using FromInnerType = optional_inner_type<FromType>::type;
        using ToInnerType = unique_ptr_inner_type_t<ToType>;
        auto return_ptr = std::make_unique<ToInnerType>();
        THROW_HR_IF_NULL(E_INVALIDARG, return_ptr.get());
        *return_ptr = ConvertToObj<FromInnerType, ToInnerType>(from_type.value(), conversion_type);
        return return_ptr;
    }

    template <typename FromType, typename ToType>
    inline std::enable_if_t<is_plain_struct_v<FromType>, std::decay_t<ToType>>
    ConvertToUniquePtr(const FromType& from_type, ConversionType conversion_type)
    {
        using FromInnerType = std::decay_t<FromType>;
        using ToInnerType = unique_ptr_inner_type_t<ToType>;
        auto return_ptr = std::make_unique<ToInnerType>();
        THROW_HR_IF_NULL(E_INVALIDARG, return_ptr.get());
        ConvertStruct(from_type, *return_ptr, conversion_type);
        return return_ptr;
    }

    template <typename FromType, typename ToType>
    inline std::enable_if_t<is_std_optional_v<ToType>&& is_unique_ptr_v<FromType>, std::decay_t<ToType>>
        ConvertToOptional(const FromType& from_type, ConversionType conversion_type)
    {
        if (!from_type)
        {
            return {};
        }

        using FromInnerType = unique_ptr_inner_type_t<FromType>;
        using ToInnerType = optional_inner_type<ToType>::type;

        return ConvertToObj<FromInnerType, ToInnerType>(*from_type, conversion_type);
    }

    template <typename FromType, typename ToType>
    inline std::enable_if_t<is_std_optional_v<ToType>&& std::is_pointer_v<FromType>, std::decay_t<ToType>>
        ConvertToOptional(const FromType& from_type, ConversionType conversion_type)
    {
        if (!from_type)
        {
            return {};
        }

        using FromInnerType = std::remove_pointer_t<std::decay_t<FromType>>;
        using ToInnerType = optional_inner_type<ToType>::type;

        return ConvertToObj<FromInnerType, ToInnerType>(*from_type, conversion_type);
    }

    template <typename FromType, typename ToType>
    inline std::enable_if_t<is_unique_ptr_v<FromType>, ToType>
        FlatbufferUniquePtrToDevTypeStruct(const FromType& from_type)
    {
        THROW_HR_IF_NULL(E_INVALIDARG, from_type.get());
        using FromInnerType = unique_ptr_inner_type_t<FromType>;
        ToType ret_type {};
        ConvertStruct<FromInnerType, ToType>(*from_type, ret_type, ConversionType::ToDevType);
        return ret_type;
    }

    template<typename T>
    inline std::wstring ConvertToStdWString(const T& wstr)
    {
        if constexpr (is_unique_ptr_v<T>)
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

    template<typename FlatbufferType>
    inline std::enable_if_t<is_unique_ptr_v<FlatbufferType>, FlatbufferType>
    CreateWStringT(const std::wstring& wchars)
    {
        using FromInnerType = unique_ptr_inner_type_t<FlatbufferType>;
        auto wchar_ptr = std::make_unique<FromInnerType>();
        THROW_IF_NULL_ALLOC(wchar_ptr);
        wchar_ptr->wchars.assign(wchars.begin(), wchars.end());
        return wchar_ptr;
    }

    template<typename FlatbufferType>
    inline std::enable_if_t<is_plain_struct_v<FlatbufferType>, FlatbufferType>
    CreateWStringT(const std::wstring& wchars)
    {
        FlatbufferType wcharT {};
        wcharT.wchars.assign(wchars.begin(), wchars.end());
        return wcharT;
        
    }

    template <typename FlatbufferType, typename DevType>
    inline DevType ConvertToDevType(const FlatbufferType& flatbuffer_type)
    {
        if constexpr (is_scalar_numeric_v<FlatbufferType> && is_scalar_numeric_v<DevType>)
        {
            return flatbuffer_type;
        }
        if constexpr (std::is_enum_v<FlatbufferType> && std::is_enum_v<DevType>)
        {
            return static_cast<DevType>(flatbuffer_type);
        }
        else if constexpr (std::is_same_v<DevType, std::string>)
        {
            return std::string(flatbuffer_type);
        }
        else if constexpr (std::is_same_v<DevType, std::wstring>)
        {
            return ConvertToStdWString(flatbuffer_type);
        }
        else if constexpr (is_unique_ptr_v<FlatbufferType> && is_unique_ptr_v<DevType>)
        {
            return ConvertToUniquePtr<FlatbufferType, DevType>(flatbuffer_type, ConversionType::ToDevType);
        }
        // Handle case where struct field in flatbuffer is std::optional but dev type is unique_ptr struct value
        else if constexpr (is_std_optional_v<FlatbufferType> && is_unique_ptr_v<DevType>)
        {
            return ConvertToUniquePtr<FlatbufferType, DevType>(flatbuffer_type, ConversionType::ToDevType);
        }
        // Handle case where struct field in flatbuffer is unique_ptr but dev type is normal struct value
        else if constexpr (is_unique_ptr_v<FlatbufferType> && is_plain_struct_v<DevType>)
        {
            return FlatbufferUniquePtrToDevTypeStruct<FlatbufferType, DevType>(flatbuffer_type);
        }
        else if constexpr (is_std_vector_v<FlatbufferType> && is_std_vector_v<DevType>)
        {
            using InnerDevType = std_vector_inner_type_t<DevType>;
            using InnerFlatbufferType = std_vector_inner_type_t<FlatbufferType>;
            DevType dev_type{};
            dev_type.reserve(flatbuffer_type.size());

            for (auto& value : flatbuffer_type)
            {
                if (is_plain_struct_v<InnerDevType>)
                {
                    InnerDevType inner_type{};
                    ConvertStruct<InnerFlatbufferType, InnerDevType>(value, inner_type, ConversionType::ToDevType);
                    dev_type.emplace_back(std::move(inner_type));
                }
                else
                {
                    dev_type.emplace_back(ConvertToDevType<InnerFlatbufferType, InnerDevType>(value));
                }
            }

            return dev_type;
        }
        else if constexpr (is_std_vector_v<FlatbufferType> && is_std_array_v<DevType>)
        {
            using InnerDevType = std_array_inner_type_t<DevType>;
            using InnerFlatbufferType = std_vector_inner_type_t<FlatbufferType>;
            DevType dev_type {};

            for (size_t i = 0; i < std::min(dev_type.size(), flatbuffer_type.size()); i++)
            {
                if (is_plain_struct_v<InnerDevType>)
                {
                    InnerDevType inner_type {};
                    ConvertStruct<InnerFlatbufferType, InnerDevType>(flatbuffer_type[i], inner_type, ConversionType::ToDevType);
                    dev_type[i] = std::move(inner_type);
                }
                else
                {
                    dev_type[i] = std::move(ConvertToDevType<InnerFlatbufferType, InnerDevType>(flatbuffer_type[i]));
                }
            }

            return dev_type;
        }

        static_assert(false, "No conversion function available for flatbuffer to dev type"  __FUNCSIG__);
    }

    template <typename DevType, typename FlatbufferType>
    inline FlatbufferType ConvertToFlatbuffer(const DevType& dev_type)
    {
        if constexpr (is_scalar_numeric_v<DevType> && is_scalar_numeric_v<FlatbufferType>)
        {
            return dev_type;
        }
        else if constexpr (std::is_enum_v<DevType> && std::is_enum_v<FlatbufferType>)
        {
            return static_cast<FlatbufferType>(dev_type);
        }
        else if constexpr (std::is_same_v<DevType, std::string>)
        {
            return std::string(dev_type);
        }
        else if constexpr (std::is_same_v<DevType, std::wstring>)
        {
            return CreateWStringT<FlatbufferType>(dev_type);
        }
        else if constexpr (is_unique_ptr_v<DevType> && is_unique_ptr_v<FlatbufferType>)
        {
            return ConvertToUniquePtr<DevType, FlatbufferType>(dev_type, ConversionType::ToFlatbuffer);
        }
        else if constexpr (std::is_pointer_v<DevType> && is_unique_ptr_v<FlatbufferType>)
        {
            return ConvertToUniquePtr<DevType, FlatbufferType>(dev_type, ConversionType::ToFlatbuffer);
        }
        else if constexpr (std::is_pointer_v<DevType> && !is_plain_struct_v<std::decay_t<DevType>>)
        {
            return ConvertToOptional<DevType, FlatbufferType>(dev_type, ConversionType::ToFlatbuffer);
        }
        else if constexpr (std::is_pointer_v<DevType> && is_plain_struct_v<std::decay_t<DevType>>)
        {
            return ConvertToUniquePtr<std::decay_t<DevType>, FlatbufferType>(dev_type, ConversionType::ToFlatbuffer);
        }
        // Handle case where struct field in flatbuffer is std::optional but dev type is unique_ptr struct value
        else if constexpr (is_std_optional_v<FlatbufferType> && is_unique_ptr_v<DevType>)
        {
            return ConvertToOptional<std::decay_t<DevType>, FlatbufferType>(dev_type, ConversionType::ToFlatbuffer);
        }
        // Handle case where struct field in flatbuffer is unique_ptr but dev type is normal struct value
        else if constexpr (is_unique_ptr_v<FlatbufferType> && is_plain_struct_v<DevType>)
        {
            return ConvertToUniquePtr<std::decay_t<DevType>, FlatbufferType>(dev_type, ConversionType::ToFlatbuffer);
        }
        else if constexpr (is_std_vector_v<DevType> && is_std_vector_v<FlatbufferType>)
        {
            using InnerDevType = std_vector_inner_type_t<DevType>;
            using InnerFlatbufferType = std_vector_inner_type_t<FlatbufferType>;
            FlatbufferType flatbuffer {};
            flatbuffer.reserve(dev_type.size());

            for (auto& value : dev_type)
            {
                if (is_plain_struct_v<InnerFlatbufferType>)
                {
                    InnerFlatbufferType inner_type {};
                    ConvertStruct<InnerDevType, InnerFlatbufferType>(value, inner_type, ConversionType::ToFlatbuffer);
                    flatbuffer.emplace_back(std::move(inner_type));
                }
                else
                {
                    flatbuffer.emplace_back(ConvertToFlatbuffer<InnerDevType, InnerFlatbufferType>(value));
                }
            }

            return flatbuffer;
        }
        else if constexpr (is_std_array_v<DevType> && is_std_vector_v<FlatbufferType>)
        {
            using InnerDevType = std_array_inner_type_t<DevType>;
            using InnerFlatbufferType = std_vector_inner_type_t<FlatbufferType>;
            FlatbufferType flatbuffer {};
            flatbuffer.reserve(dev_type.size());

            for (size_t i = 0; i < dev_type.size(); i++)
            {
                if (is_plain_struct_v<InnerFlatbufferType>)
                {
                    InnerFlatbufferType inner_type {};
                    ConvertStruct<InnerDevType, InnerFlatbufferType>(dev_type[i], inner_type, ConversionType::ToFlatbuffer);
                    flatbuffer.emplace_back(std::move(inner_type));
                }
                else
                {
                    flatbuffer.emplace_back(ConvertToFlatbuffer<InnerDevType, InnerFlatbufferType>(dev_type[i]));
                }
            }

            return flatbuffer;
        }

        static_assert(false, "No conversion function available for dev type to flatbuffer"  __FUNCSIG__);
    }

    template <typename From, typename To, size_t... I>
    inline std::enable_if_t<is_plain_struct_v<From>&& is_plain_struct_v<To>, void>
    ConvertStructImpl(const From& from, To& to, ConversionType conversion_type, std::index_sequence<I...>)
    {
        (
            (
                [&] {
                    auto& src_field = from.*(std::get<I>(StructMetaData<From>::members));
                    auto& dst_field = to.*(std::get<I>(StructMetaData<To>::members));
                    using SrcT = std::decay_t<decltype(src_field)>;
                    using DstT = std::decay_t<decltype(dst_field)>;

                    if (is_plain_struct_v<SrcT> && is_plain_struct_v<DstT>)
                    {
                        ConvertStruct(src_field, dst_field, conversion_type);
                    }
                    else if (conversion_type == ConversionType::ToDevType)
                    {
                        dst_field = std::move(ConvertToDevType<SrcT, DstT>(src_field));
                    }
                    else
                    {
                        dst_field = std::move(ConvertToFlatbuffer<SrcT, DstT>(src_field));
                    }
                }()
            ), ...
        );
    }

    template <typename From, typename To>
    inline std::enable_if_t<is_plain_struct_v<From> && is_plain_struct_v<To>, void>
        ConvertStruct(const From& from, To& to, ConversionType conversion_type)
    {
        constexpr size_t N = StructMetaData<From>::count;
        static_assert(N == StructMetaData<To>::count, "Structs must have the same number of fields!");
        ConvertStructImpl<From, To>(from, to, conversion_type, std::make_index_sequence<N>{});
    }

    template <typename From, typename To>
    inline std::enable_if_t<!is_plain_struct_v<From> || !is_plain_struct_v<To>, void>
        ConvertStruct(const From& from, To& to, ConversionType conversion_type)
    {
    }
}

