###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Multiple Vulnerabilities - Nov09
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
  script_oid("1.3.6.1.4.1.25623.1.0.900889");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-17 15:16:05 +0100 (Tue, 17 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2816", "CVE-2009-2842", "CVE-2009-3384");
  script_bugtraq_id(36997, 36994, 36995);
  script_name("Apple Safari Multiple Vulnerabilities - Nov09");


  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, disclose sensitive information, or compromise a user's system.");
  script_tag(name:"affected", value:"Apple Safari version prior to 4.0.4");
  script_tag(name:"insight", value:"- An error exists in WebKit when sending 'preflight' requests originating
    from a page in a different origin. This can be exploited to facilitate
    cross-site request forgery attacks by injecting custom HTTP headers.

  - An error exists when handling an 'Open Image in New Tab', 'Open Image in'
    'New Window', or 'Open Link in New Tab' shortcut menu action performed on
    a link to a local file. This can be exploited to load a local HTML file
    and disclose sensitive information by tricking a user into performing the
    affected actions within a specially crafted webpage.

  - Multiple errors in WebKit when handling FTP directory listings can be
    exploited to disclose sensitive information.");
  script_tag(name:"solution", value:"Upgrade to Safari version 4.0.4 or latest version.");
  script_tag(name:"summary", value:"This host has Apple Safari installed and is prone to multiple
  vulnerabilities.");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3949");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37346");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Nov/msg00001.html");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer)
  exit(0);

if(version_is_less(version:safariVer, test_version:"5.31.21.11")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
