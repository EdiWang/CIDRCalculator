using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace CIDRCalc.Pages
{
    public partial class Index
    {
        [Inject]
        public IJSRuntime JavaScriptRuntime { get; set; }
    }
}
