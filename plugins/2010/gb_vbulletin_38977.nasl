###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_38977.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# vBulletin Multiple Unspecified Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100557");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-29 12:55:36 +0200 (Mon, 29 Mar 2010)");
  script_bugtraq_id(38977);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("vBulletin Multiple Unspecified Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38977");
  script_xref(name:"URL", value:"http://www.vbulletin.com/forum/showthread.php?346761-Security-Patch-Release-4.0.2-PL3");
  script_xref(name:"URL", value:"http://www.vbulletin.com/forum/showthread.php?346897-Security-Patch-Release-4.0.2-PL4");
  script_xref(name:"URL", value:"http://www.vbulletin.com/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor released updates to address these issues. Please see the
  references for more information.");
  script_tag(name:"summary", value:"vBulletin is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input.

  An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks.

  vBulletin versions prior to 4.0.2 PL4 are vulnerable.");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(vers = get_version_from_kb(port:port,app:"vBulletin")) {

  if(version_is_less(version: vers, test_version: "4.0.2.PL4")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
