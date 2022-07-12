###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sitescope_47554.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HP SiteScope Cross Site Scripting and HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:sitescope";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103149");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
  script_bugtraq_id(47554);
  script_cve_id("CVE-2011-1726", "CVE-2011-1727");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("HP SiteScope Cross Site Scripting and HTML Injection Vulnerabilities");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_hp_sitescope_detect.nasl");
  script_mandatory_keys("hp/sitescope/installed");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"HP SiteScope is prone to a cross-site scripting vulnerability and an
HTML-injection vulnerability because it fails to properly sanitize user-supplied input before using it in
dynamically generated content.

Successful exploits will allow attacker-supplied HTML and script code to run in the context of the affected
browser, potentially allowing the attacker to steal cookie-based authentication credentials or to control how the
site is rendered to the user. Other attacks are also possible.

HP SiteScope versions 9.54, 10.13, 11.01, and 11.1 are affected.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/47554");
  script_xref(name:"URL", value:"https://h10078.www1.hp.com/cda/hpms/display/main/hpms_content.jsp?zn=bto&cp=1-11-15-25%5E849_4000_100__");
  script_xref(name:"URL", value:"http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02807712");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_equal(version:version, test_version:"9.54")  ||
   version_is_equal(version:version, test_version:"10.13") ||
   version_is_equal(version:version, test_version:"11.01")) {
     security_message(port:port);
  exit(0);
}
