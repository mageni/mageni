# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flashpixx:evalphp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104713");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-04-25 14:08:54 +0000 (Tue, 25 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("WordPress 'Eval PHP' Plugin Abandoned");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/evalphp/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Eval PHP' is abandoned and shouldn't be
  used anymore.");

  script_tag(name:"vuldetect", value:"Checks if the plugin is present on the target host.");

  script_tag(name:"insight", value:"- The plugin was updated on 10/2012 the last time, needs to be
  seen as abandoned and could pose a security risk for the remote host.

  - On 04/2023 a spike of installations of this plugin has been observed. After analysis it was
  determined that malicious threat actors are misusing this plugin to plant backdoors on an affected
  host. Based on this information the remote host should be seen as compromised if this plugin
  wasn't installed on purpose.");

  script_tag(name:"affected", value:"WordPress 'Eval PHP' plugin in all versions.");

  script_tag(name:"solution", value:"- Remove the plugin from the remote host as it could pose
  a security risk due to the abandoned status

  - If the plugin wasn't installed on purpose: The remote host could be compromised and a whole
  cleanup of the infected system might be required");

  script_xref(name:"URL", value:"https://blog.sucuri.net/2023/04/massive-abuse-of-abandoned-evalphp-wordpress-plugin.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
security_message( port: port, data: report );
exit( 0 );
