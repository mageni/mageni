###############################################################################
# OpenVAS Vulnerability Test
#
# Neon Certificate Spoofing And Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900828");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2473", "CVE-2009-2474");
  script_bugtraq_id(36080, 36079);
  script_name("Neon Certificate Spoofing and Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36371");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52633");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2341");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_neon_detect.nasl");
  script_mandatory_keys("WebDAV/Neon/Ver");
  script_tag(name:"impact", value:"Attacker may leverage this issue to conduct man-in-the-middle attacks to
  spoof arbitrary SSL servers, and can deny the service by memory or CPU
  consumption on the affected application.");
  script_tag(name:"affected", value:"WebDAV, Neon version prior to 0.28.6 on Linux.");
  script_tag(name:"insight", value:"- When OpenSSL is used, neon does not properly handle a '&qt?&qt' character
  in a domain name in the 'subject&qts' Common Name (CN) field of an X.509
  certificate via a crafted certificate issued by a legitimate Certification Authority.

  - When expat is used, neon does not properly detect recursion during entity
  expansion via a crafted XML document containing a large number of nested entity references.");
  script_tag(name:"solution", value:"Upgrade to version 0.28.6 or later.");
  script_tag(name:"summary", value:"This host has Neon installed and is prone to Certificate Spoofing
  and Denial of Service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

neonVer = get_kb_item("WebDAV/Neon/Ver");
if(!neonVer)
  exit(0);

if(version_is_less(version:neonVer, test_version:"0.28.6")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
