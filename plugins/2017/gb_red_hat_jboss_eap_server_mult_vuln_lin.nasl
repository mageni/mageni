###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_red_hat_jboss_eap_server_mult_vuln_lin.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Red Hat JBoss EAP Server Multiple Vulnerabilities (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810320");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2015-5220", "CVE-2015-5188", "CVE-2015-5178");
  script_bugtraq_id(77345, 77346, 68444);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-04 14:39:58 +0530 (Wed, 04 Jan 2017)");
  script_name("Red Hat JBoss EAP Server Multiple Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is running Red Hat JBoss EAP Server
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - The EAP console does not set the X-Frame-Options HTTP header.

  - The web Console does not properly validate a file upload using a
    multipart/form-data submission.

  - A Java OutOfMemoryError in the HTTP management interface while sending
    requests containing large headers to Web Console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct clickjacking attack, to cause a denial of service,
  and hijack the authentication of administrators for requests that make
  arbitrary changes to an instance and to read arbitrary files.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"affected", value:"Red Hat JBoss EAP server versions before
  6.4.4 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Red Hat JBoss EAP server 6.4.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1250552");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1252885");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1255597");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2015-1908.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(version_is_less(version:jbossVer, test_version:"6.4.4"))
{
  report = report_fixed_ver( installed_version:jbossVer, fixed_version:"6.4.4");
  security_message(data:report, port:jbossPort);
  exit(0);
}

exit(0);
