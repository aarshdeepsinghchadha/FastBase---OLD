﻿using Domain.Admin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Admin
{
    public class DecodeTokenDto
    {
        public bool Status { get; set; }
        public AppUser UserDetails { get; set; }
    }
}
