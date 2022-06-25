###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_39150.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Moodle Prior to 1.9.8/1.8.12 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100569");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
  script_bugtraq_id(39150);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Moodle Prior to 1.9.8/1.8.12 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39150");
  script_xref(name:"URL", value:"http://docs.moodle.org/en/Moodle_1.9.8_release_notes");
  script_xref(name:"URL", value:"http://www.moodle.org");
  script_xref(name:"URL", value:"http://moodle.org/security/");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Moodle/Version");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities, including:

  - multiple cross-site scripting issues

  - a security-bypass issue

  - an information-disclosure issue

  - multiple SQL-injection issues

  - an HTML-injection issue

  - a session-fixation issue");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
restrictions, obtain sensitive information, perform unauthorized
actions, compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database. Other attacks may
also be possible.");

  script_tag(name:"affected", value:"These issues affect versions prior to Moodle 1.9.8 and 1.8.12.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(vers = get_version_from_kb(port:port,app:"moodle")) {

  if(vers =~ "1\.8") {

    if(version_is_less(version: vers, test_version: "1.8.9")) {
      security_message(port:port);
      exit(0);
    }

  } else if(vers =~ "1\.9") {

    if(version_is_less(version: vers, test_version: "1.9.8")) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(0);
