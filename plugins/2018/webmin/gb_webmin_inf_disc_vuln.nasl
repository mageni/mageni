###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webmin_inf_disc_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Webmin 1.880 Information Disclosure Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113135");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-03-15 13:16:22 +0100 (Thu, 15 Mar 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2018-8712");

  script_name("Webmin 1.880 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to an information disclosure vulnerability that allows non-privileged users to access arbitrary files.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An issue was discovered in Webmin when the default Yes setting of 'Can view any file as a log file' is enabled.
  As a result of weak default configuration settings, limited users have full access rights to the underlying Unix system files, allowing the user to
  read sensitive data from the local system (using Local File Include) such as the '/etc/shadow' file via a 'GET /syslog/save_log.cgi?view=1&file=/etc/shadow' request.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access any file on the system, ranging from sensitive documents to administrator passwords.");
  script_tag(name:"affected", value:"Webmin through version 1.880");
  script_tag(name:"solution", value:"No patch is available as of 15th March, 2018. As a mitigation technique, the setting 'Can view any file as a log file' can be disabled,
  effectively stopping a user from exploiting this vulnerability.");

  script_xref(name:"URL", value:"https://www.7elements.co.uk/resources/technical-advisories/webmin-1-840-1-880-unrestricted-access-arbitrary-files-using-local-file-include/");
  script_xref(name:"URL", value:"http://www.webmin.com/changes.html");

  exit(0);
}

CPE = "cpe:/a:webmin:webmin";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

# The 7elements PoC only includes 1.840 and 1.880, because these were the versions that were tested
# But as the feature was available from the beginning, one can safely assume that all versions are affected
if( version_is_less_equal( version: version, test_version: "1.880" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Please see the solution tag for an available Mitigation" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
