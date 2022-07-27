###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_xml_dos_vuln_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Opera Web Browser XML Denial Of Service Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800550");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1234");
  script_bugtraq_id(34298);
  script_name("Opera Web Browser XML Denial Of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8320");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49522");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a malicious XML page
  and cause denial of service by persuading the user to open the malicious
  arbitrary page.");
  script_tag(name:"affected", value:"Opera version 9.64 and prior on Windows.");
  script_tag(name:"insight", value:"This flaw is due to improper boundary check while parsing XML
  documents containing an overly large number of nested elements.");
  script_tag(name:"solution", value:"Upgrade to Opera version 10.00 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera Web Browser and is prone to
  XML Denial of Service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com/download");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less_equal(version:operaVer, test_version:"9.64")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
