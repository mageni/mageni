###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Multiple Vulnerabilities Feb-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900311");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353");
  script_bugtraq_id(33598);
  script_name("Mozilla Thunderbird Multiple Vulnerabilities Feb-09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33799");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Thunderbird/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation may let the attacker cause remote code execution
  or may cause memory/application crash to conduct denial of service attack.");
  script_tag(name:"affected", value:"Thunderbird version prior to 2.0.0.21 on Linux.");
  script_tag(name:"insight", value:"Flaws are in vectors related to the layout engine and destruction of
  arbitrary layout objects by the 'nsViewManager::Composite' function.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird version 2.0.0.21.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Thunderbird and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(!tbVer)
  exit(0);

if(version_is_less(version:tbVer, test_version:"2.0.0.21")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
