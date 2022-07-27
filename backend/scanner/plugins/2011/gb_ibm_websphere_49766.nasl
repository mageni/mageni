###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_49766.nasl 13803 2019-02-21 08:24:24Z cfischer $
#
# IBM WebSphere Application Server Cross-Site Request Forgery Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103277");
  script_version("$Revision: 13803 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-09-28 12:51:43 +0200 (Wed, 28 Sep 2011)");
  script_bugtraq_id(49766);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("IBM WebSphere Application Server Cross-Site Request Forgery Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49766");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24030916");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27022958#8001");
  script_xref(name:"URL", value:"http://www-01.ibm.com/software/websphere/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Vendor fixes are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a cross-site request
  forgery vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue may allow a remote attacker to perform certain
  actions in the context of an authorized user and gain access to the affected application. Other attacks are also possible.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions prior to 8.0.0.1 are
  vulnerable. Other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less(version:vers, test_version:"8.0.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.0.0.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);