###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari DoS or XSS Vulnerability - July09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800834");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-07-12 15:16:55 +0200 (Sun, 12 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1724", "CVE-2009-1725");
  script_bugtraq_id(35441, 35607);
  script_name("Apple Safari DoS or XSS Vulnerability - July09");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3666");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Jul/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code and can
  cause memory corruption, XSS attacks and can deny the service in the victim's
  system.");
  script_tag(name:"affected", value:"Apple Safari version prior to 4.0.2 on Windows.");
  script_tag(name:"insight", value:"- Error in 'WebKit' is allow user to inject arbitrary web script or HTML via
    vectors related to parent and top objects.

  - Error in 'WebKit' is fails to handle numeric character references via a
    crafted HTML document.");
  script_tag(name:"solution", value:"Upgrade to Safari version 4.0.2 (4.30.19.1).");
  script_tag(name:"summary", value:"This host is installed with Apple Safari Web Browser and is prone to Denial
  of Service or Cross-Site Scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer)
  exit(0);

if(version_is_less(version:safariVer, test_version:"4.30.19.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
