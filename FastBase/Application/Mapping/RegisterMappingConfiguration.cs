using Application.Admin;
using AutoMapper;
using Domain.Admin;

namespace Application.Mapping
{
    public class RegisterMappingConfiguration : Profile
    {
        public RegisterMappingConfiguration()
        {
            CreateMap<RegisterDto, AppUser>()
                .ForMember(dest => dest.FirstName, opt => opt.MapFrom(src => src.FirstName))
                .ForMember(dest => dest.LastName, opt => opt.MapFrom(src => src.LastName))
                .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.Username))
                .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
                .ForMember(dest => dest.PhoneNumber, opt => opt.MapFrom(src => src.PhoneNumber));
        }
    }
}
