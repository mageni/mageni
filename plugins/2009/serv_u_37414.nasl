###############################################################################
# OpenVAS Vulnerability Test
# $Id: serv_u_37414.nasl 13608 2019-02-12 14:34:26Z cfischer $
#
# Serv-U File Server User Directory Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100410");
  script_version("$Revision: 13608 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 15:34:26 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-12-21 12:36:27 +0100 (Mon, 21 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4815");
  script_bugtraq_id(37414);
  script_name("Serv-U File Server User Directory Information Disclosure Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_rhinosoft_serv-u_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("Serv-U/FTP/Ver");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references
  for details.");

  script_tag(name:"summary", value:"Serv-U File Server is prone to an unspecified information-disclosure
  vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to harvest sensitive information that
  may lead to further attacks.");

  script_tag(name:"affected", value:"Versions prior to SERV-U File Server 9.2.0.1 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37414");
  script_xref(name:"URL", value:"http://www.serv-u.com/releasenotes/");
  script_xref(name:"URL", value:"http://www.serv-u.com/");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port(default:21);

if(!version = get_kb_item(string("ftp/", port, "/Serv-U"))) {
  if(!version = get_kb_item(string("Serv-U/FTP/Ver"))) {
    exit(0);
  }
}

if(!isnull(version[1])) {
  vers = version[1];
}

if(!isnull(vers)) {
  if(vers =~ "^9\.") {
    if(version_is_less(version:vers, test_version:"9.2.0.1") ) {
      security_message(port: port);
      exit(0);
    }
  }
}

exit(0);