###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_red_hat_jboss_eap_server_dos_vuln01_lin.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Red Hat JBoss EAP Server Denial of Service Vulnerability01 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810314");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2015-5304");
  script_bugtraq_id(79788);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-16 19:22:06 +0530 (Fri, 16 Dec 2016)");
  script_name("Red Hat JBoss EAP Server Denial of Service Vulnerability01 (Linux)");

  script_tag(name:"summary", value:"This host is running Red Hat JBoss EAP Server
  and is prone to denial of service Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to red hat JBoss
  enterprise application platform does not properly authorize access to shut
  down the server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users with the monitor, deployer, or auditor role to cause a
  denial of service.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Red Hat JBoss EAP server versions before
  6.4.5 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Red Hat JBoss EAP server version
  6.4.5 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2015-2541.html");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_red_hat_jboss_eap_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Redhat/JBoss/EAP/Installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 443);
  script_xref(name:"URL", value:"http://jbossas.jboss.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jbossPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!jbossVer = get_app_version(cpe:CPE, port:jbossPort)){
  exit(0);
}

if(version_is_less(version:jbossVer, test_version:"6.4.5"))
{
  report = report_fixed_ver( installed_version:jbossVer, fixed_version:"6.4.5");
  security_message( data:report, port:jbossPort);
  exit(0);
}
exit(0);
