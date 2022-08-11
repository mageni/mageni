# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117687");
  script_version("2021-09-20T09:56:41+0000");
  script_tag(name:"last_modification", value:"2021-09-21 10:10:27 +0000 (Tue, 21 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-20 09:40:32 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2021-09-20 09:40:32 +0000 (Mon, 20 Sep 2021)");

  script_name("Weak Host Key Algorithm(s) (SSH)");

  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_tag(name:"solution_type", value:"Mitigation");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ssh_algos.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/algos_available");

  script_tag(name:"summary", value:"The remote SSH server is configured to allow / support weak host
  key algorithm(s).");

  script_tag(name:"vuldetect", value:"Checks the supported host key algorithms of the remote SSH
  server.

  Currently weak host key algorithms are defined as the following:

  - ssh-dss: Digital Signature Algorithm (DSA) / Digital Signature Standard (DSS)");

  script_tag(name:"solution", value:"Disable the reported weak host key algorithm(s).");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = ssh_get_port( default:22 );

weak_host_key_algos = make_array( "ssh-dss", "Digital Signature Algorithm (DSA) / Digital Signature Standard (DSS)" );

if( ! supported_host_key_algos = get_kb_list( "ssh/" + port + "/server_host_key_algorithms" ) )
  exit( 0 );

found_weak_host_key_algo = FALSE;
weak_host_key_algos_report = make_array();

foreach weak_host_key_algo( keys( weak_host_key_algos ) ) {
  if( in_array( search:weak_host_key_algo, array:supported_host_key_algos, part_match:FALSE ) ) {
    weak_host_key_algos_report[weak_host_key_algo] = weak_host_key_algos[weak_host_key_algo];
    found_weak_host_key_algo = TRUE;
  }
}

if( found_weak_host_key_algo ) {
  report = '\n\n' + text_format_table( array:weak_host_key_algos_report, sep:" | ", columnheader:make_list( "host key algorithm", "Description" ) );
  log_message( port:port, data:"The remote SSH server supports the following weak host key algorithm(s):" + report );
  exit( 0 );
}

exit( 99 );