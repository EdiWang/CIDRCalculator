using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace CIDRCalc.Pages
{
    public partial class Index
    {
        [Inject]
        public IJSRuntime JavaScriptRuntime { get; set; }

        public string StartIP { get; set; }

        public string EndIP { get; set; }

        public IEnumerable<CIDR> CIDRs { get; set; }

        public Index()
        {
            CIDRs = Array.Empty<CIDR>();
        }

        private void GetCIDRs()
        {
            var startAddress = IPAddress.Parse(StartIP);
            var endAddress = IPAddress.Parse(EndIP);

            CIDRs = CIDR.Split(startAddress, endAddress);
        }
    }
}
