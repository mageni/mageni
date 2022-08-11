###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_shibboleth_xml_dos_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Shibboleth XML Security Signature Key Parsing Denial of Service Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802223");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_cve_id("CVE-2011-2516");
  script_bugtraq_id(48611);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Shibboleth XML Security Signature Key Parsing Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45191");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68420");
  script_xref(name:"URL", value:"http://shibboleth.internet2.edu/secadv/secadv_20110706.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_shibboleth_sp_detect_win.nasl");
  script_mandatory_keys("Shibboleth/SP/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause the application
  to crash, resulting in denial-of-service conditions.");
  script_tag(name:"affected", value:"Shibboleth versions prior to 2.4.3");
  script_tag(name:"insight", value:"The flaw is due to off-by-one error in the XML signature feature in
  Apache XML Security, allows remote attackers to cause a denial of service
  via a signature using a large RSA key, which triggers a buffer overflow.");
  script_tag(name:"solution", value:"Upgrade to Shibboleth version 2.4.3 or later.");
  script_tag(name:"summary", value:"This host is installed with Shibboleth and is prone to denial of
  service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://shibboleth.internet2.edu/downloads.html");
  exit(0);
}


include("version_func.inc");

version = get_kb_item("Shibboleth/SP/Win/Ver");
if(version)
{
  if(version_is_less(version:version, test_version:"2.4.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
