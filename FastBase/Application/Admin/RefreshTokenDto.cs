﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Admin
{
    public class RefreshTokenDto
    {
        public string OldToken { get; set; }
        public string Email { get; set; }
    }
}
