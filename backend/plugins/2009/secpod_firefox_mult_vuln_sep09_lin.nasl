###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Multiple Vulnerabilities - Sep09 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900847");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3072", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
  script_bugtraq_id(36343);
  script_name("Mozilla Firefox Multiple Vulnerabilities - Sep09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36671/");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-47.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-49.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-50.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-51.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"A remote, unauthenticated attacker could execute arbitrary code or cause a
  vulnerable application to crash.");
  script_tag(name:"affected", value:"Mozilla Firefox version prior to 3.0.14 and 3.5 before 3.5.3 on Linux.");
  script_tag(name:"insight", value:"- Multiple errors in the browser and JavaScript engines can be exploited to
    corrupt memory.

  - An error exists when processing operations performed on the columns of a
    XUL tree element. This can be exploited to dereference freed memory via a
    pointer owned by a column of the XUL tree element.

  - An error exists when displaying text in the location bar using the default
    Windows font. This can be exploited to spoof the URL of a trusted site via
    Unicode characters having a tall line-height.

  - An error in the implementation of the 'BrowserFeedWriter' object can be
    exploited to execute arbitrary JavaScript code with chrome privileges.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.14 or 3.5.3 or later.");
  script_tag(name:"summary", value:"The host is installed with Firefox browser and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_is_less(version:ffVer, test_version:"3.0.14") ||
   version_in_range(version:ffVer,test_version:"3.5", test_version2:"3.5.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
