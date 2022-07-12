###############################################################################
# OpenVAS Vulnerability Test
# $Id: symantec_ws_dos.nasl 10781 2018-08-06 07:41:20Z cfischer $
#
# Symantec Web Security flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2007 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.80020");
  script_version("$Revision: 10781 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-06 09:41:20 +0200 (Mon, 06 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2007-0563", "CVE-2007-0564");
  script_bugtraq_id(22184);
  script_name("Symantec Web Security flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2007 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("symantec_ws_detection.nasl");
  script_require_ports("Services/www", 8002);
  script_mandatory_keys("SymantecWS/installed");

  script_tag(name:"solution", value:"Upgrade at least to version 3.0.1.85.");

  script_tag(name:"summary", value:"The remote service is affected by multiple vulnerabilities.

  Description :

  According to its banner, the version of Symantec Web Security on the remote host is vulnerable
  to denial of service and cross-site scripting attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:8002 );

version = get_kb_item(string("www/", port, "/SWS"));
if (version) {
  if (ereg(pattern:"^(2\.|3\.0\.(0|1\.([0-9]|[1-7][0-9]|8[0-4])$))", string:version)) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);