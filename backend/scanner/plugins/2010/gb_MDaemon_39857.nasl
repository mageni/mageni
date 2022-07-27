###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_MDaemon_39857.nasl 13467 2019-02-05 12:16:48Z cfischer $
#
# Alt-N MDaemon SUBSCRIBE Remote Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100630");
  script_version("$Revision: 13467 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 13:16:48 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-05-06 13:19:12 +0200 (Thu, 06 May 2010)");
  script_bugtraq_id(39857);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Alt-N MDaemon SUBSCRIBE Remote Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/mdaemon/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39857");
  script_xref(name:"URL", value:"http://www.altn.com/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/May/9");

  script_tag(name:"summary", value:"MDaemon is prone to an information-disclosure vulnerability because it
  fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to gain access to
  information from arbitrary files on the vulnerable server.");

  script_tag(name:"affected", value:"MDaemon 11.0.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("version_func.inc");

port = get_smtp_port(default:25);

banner = get_smtp_banner(port:port);
if(!banner || "MDaemon" >!< banner)
  exit(0);

vers = eregmatch(pattern:"MDaemon[^0-9]+([0-9.]+);", string:banner);
if(!vers[1])
  exit(0);

if(version_in_range(version:vers[1], test_version:"11.0.0", test_version2:"11.0.1")) {
  report = report_fixed_ver(installed_version:vers[1], fixed_version:"Unknown");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);