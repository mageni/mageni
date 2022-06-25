###############################################################################
# OpenVAS Vulnerability Test
#
# HTML-Parser 'decode_entities()' Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801039");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3627");
  script_bugtraq_id(36807);
  script_name("HTML-Parser 'decode_entities()' Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37155");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53941");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/10/23/9");
  script_xref(name:"URL", value:"https://issues.apache.org/SpamAssassin/show_bug.cgi?id=6225");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_html_parser_detect_lin.nasl");
  script_mandatory_keys("HTML-Parser/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition.");
  script_tag(name:"affected", value:"HTML-Parser versions prior to 3.63 on Linux.");
  script_tag(name:"insight", value:"The flaw is due to an error within the 'decode_entities()' function in 'utils.c',
  which can be exploited to cause an infinite loop by tricking an application into
  processing a specially crafted string using this library.");
  script_tag(name:"summary", value:"This host is installed with HTML-Parser and is prone to Denial of
  Service Vulnerability.");
  script_tag(name:"solution", value:"Upgrade to HTML-Parser version 3.63 or later.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

parserVer = get_kb_item("HTML-Parser/Linux/Ver");
if(!parserVer)
  exit(0);

if(version_is_less(version:parserVer, test_version:"3.63")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
