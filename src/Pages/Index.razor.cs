using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Net;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace CIDRCalc.Pages
{
    public partial class Index
    {
        [Inject]
        public IJSRuntime JavaScriptRuntime { get; set; }

        public IPRange2CIDRModel IPRange2CIDRModel { get; set; }

        public CIDR2IPRangeModel CIDR2IPRangeModel { get; set; }

        public IEnumerable<CIDR> CIDRs { get; set; }

        public string IPRange { get; set; }

        public Index()
        {
            IPRange2CIDRModel = new();
            CIDR2IPRangeModel = new();
            CIDRs = Array.Empty<CIDR>();
        }

        private void GetCIDRs()
        {
            var startAddress = IPAddress.Parse(IPRange2CIDRModel.StartIP);
            var endAddress = IPAddress.Parse(IPRange2CIDRModel.EndIP);

            CIDRs = CIDR.Split(startAddress, endAddress);
        }

        private void GetIPRange()
        {
            var inputCIDR = CIDR2IPRangeModel.CIDR.Split('/');
            if (inputCIDR.Length > 1)
            {
                var fromCidr = new CIDR(IPAddress.Parse(inputCIDR[0]), uint.Parse(inputCIDR[1]));
                IPRange = $"{fromCidr.NetworkAddress} - {fromCidr.LastAddress}";
            }
            else
            {
                IPRange = inputCIDR[0];
            }
        }
    }

    public class IPRange2CIDRModel
    {
        [Required]
        [RegularExpression(@"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ErrorMessage = "Please input a valid IPv4 Address")]
        public string StartIP { get; set; }

        [Required]
        [RegularExpression(@"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ErrorMessage = "Please input a valid IPv4 Address")]
        public string EndIP { get; set; }
    }

    public class CIDR2IPRangeModel
    {
        [Required]
        [RegularExpression(@"^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$", ErrorMessage = "Please input a vlid IPv4 CIDR")]
        public string CIDR { get; set; }
    }
}
