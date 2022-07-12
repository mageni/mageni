# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80087");
  script_version("2020-10-08T13:07:46+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-24 10:51:07 +0000 (Thu, 24 Sep 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("SSF Service");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("ssh_ssf.nasl");
  script_mandatory_keys("ssf/detected");

  script_tag(name:"summary", value:"The SSF service is running on the target host.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"According to its banner, the remote SSH server is the
  SSF derivative.

  SSF had been written to be compliant with restrictive
  laws on cryptography in some European countries, France
  especially.

  These regulations have been softened and OpenSSH received
  a formal authorisation from the French administration in
  2002 and the development of SSF has been discontinued.

  SSF is based upon an old version of OpenSSH and it implements
  an old version of the protocol. As it is not maintained anymore,
  it might be vulnerable to dangerous flaws.");

  script_tag(name:"solution", value:"Remove SSF and install an up to date version of OpenSSH.");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( "ssf/port" ) ) exit( 0 );

report = "The 'SSF' service was discovered on the target system.";
security_message( data: report, port: port );

exit( 0 );
