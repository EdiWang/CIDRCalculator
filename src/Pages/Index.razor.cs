using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
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

        public IPRange2CIDRModel IPRange2CIDRModel { get; set; }

        public IEnumerable<CIDR> CIDRs { get; set; }

        public Index()
        {
            IPRange2CIDRModel = new ();
            CIDRs = Array.Empty<CIDR>();
        }

        private void GetCIDRs()
        {
            var startAddress = IPAddress.Parse(IPRange2CIDRModel.StartIP);
            var endAddress = IPAddress.Parse(IPRange2CIDRModel.EndIP);

            CIDRs = CIDR.Split(startAddress, endAddress);
        }
    }

    public class IPRange2CIDRModel
    {
        [Required]
        public string StartIP { get; set; }

        [Required]
        public string EndIP { get; set; }
    }
}
