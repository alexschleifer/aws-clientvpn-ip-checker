// This function requires the input described in:
// https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/connection-authorization.html

use aws_lambda_events::clientvpn;
use lambda_runtime::{service_fn, tracing, Error, LambdaEvent};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json;
use tracing::{error, info, Level};
//use tracing_subscriber;

//#[derive(Deserialize)]
//struct Request {
//    #[serde(rename = "connection-id")]
//    connection_id: String,
//    #[serde(rename = "endpoint-id")]
//   endpoint_id: String,
//   #[serde(rename = "common-name")]
//   common_name: String,
//   username: String,
//   platform: String,
//   #[serde(rename = "platform-version")]
//   platform_version: String,
//   #[serde(rename = "public-ip")]
//   public_ip: String,
//   #[serde(rename = "client-openvpn-version")]
//   client_openvpn_version: String,
//   groups: String,
//   #[serde(rename = "schema-version")]
//   schema_version: String,
//}

#[derive(Deserialize)]
pub struct ClientVpnConnectionHandlerRequest {
    pub connection_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub common_name: Option<String>,
    pub username: Option<String>,
    pub os_platform: Option<String>,
    pub os_platform_version: Option<String>,
    pub public_ip: Option<String>,
    pub client_open_vpn_version: Option<String>,
    pub groups: Option<String>, // not in original rust struct documentation
    pub schema_version: Option<String>,
}

//#[derive(Serialize)]

//struct Response {
// message should be removed from responce json
//    message: String,

//    allow: bool,
//    #[serde(rename = "error-msg-on-denied-connection")]
//    error_msg_on_denied_connection: String,
//    #[serde(rename = "posture-compliance-statuses")]
//    posture_compliance_statuses : String,
//    #[serde(rename = "schema-version")]
//    schema_version: String,
//}

#[derive(Serialize)]
pub struct ClientVpnConnectionHandlerResponse {
    pub allow: bool,
    pub error_msg_on_failed_posture_compliance: Option<String>,
    pub posture_compliance_statuses: Vec<String>,
    pub schema_version: Option<String>,
}

#[derive(Deserialize)]
struct IpInfoResponse {
    country: String,
    city: String,
    org: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // required to enable CloudWatch error logging by the runtime
    tracing::init_default_subscriber();

    // let subscriber = FmtSubscriber::builder()
    //    .with_max_level(Level::INFO)
    //    .finish();

    // tracing::subscriber::fmt()
    //    .expect("setting default subscriber failed");

    let func = service_fn(my_handler);
    lambda_runtime::run(func).await?;
    Ok(())
}

pub(crate) async fn my_handler(
    _event: LambdaEvent<ClientVpnConnectionHandlerRequest>,
) -> Result<ClientVpnConnectionHandlerResponse, Error> {
    // extract some useful info from the request

    let allowed_country = ["IL", "US", "JP"]; // according to https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
    let _connection_id = _event.payload.connection_id;
    let _endpoint_id = _event.payload.endpoint_id;
    let _common_name = _event.payload.common_name;
    let _username = _event.payload.username;
    let _platform = _event.payload.os_platform;
    let _platform_version = _event.payload.os_platform_version;
    let _client_openvpn_version = _event.payload.client_open_vpn_version;
    let _groups = _event.payload.groups;
    let _schema_version = _event.payload.schema_version;
    let _ip_address = _event.payload.public_ip;
    //let url = format!("https://ipinfo.io/{}",_ip_address);
    let url = match _ip_address {
        Some(ip) => format!("https://ipinfo.io/{}", ip),
        None => {
            error!("No ip address provided");
            return Ok(ClientVpnConnectionHandlerResponse {
                allow: false,
                error_msg_on_failed_posture_compliance: Some(String::from("Deny")),
                posture_compliance_statuses: vec![String::from("Unknown")],
                schema_version: Some(String::from("v2")),
            });
        }
    };

    let check_ip_resp = match reqwest::get(&url).await {
        Ok(resp) => resp.text().await?,
        Err(e) => {
            error!("Failed to get ipinfo response: {}", e);
            return Ok(ClientVpnConnectionHandlerResponse {
                allow: false,
                error_msg_on_failed_posture_compliance: Some(String::from("Deny")),
                posture_compliance_statuses: vec![String::from("Unknown")],
                schema_version: Some(String::from("v2")),
            });
        }
    };
    let check_ip_info: IpInfoResponse = match serde_json::from_str(&check_ip_resp) {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to parse ipinfo response: {}", e);
            return Ok(ClientVpnConnectionHandlerResponse {
                allow: false,
                error_msg_on_failed_posture_compliance: Some(String::from("Deny")),
                posture_compliance_statuses: vec![String::from("Unknown")],
                schema_version: Some(String::from("v2")),
            });
        }
    };

    let user_coutry = check_ip_info.country;
    let user_city = check_ip_info.city;
    let _user_org = check_ip_info.org;
    // prepare the response

    let msg_deny = format!(
        "Connection from {}, {} is not allowed.",
        user_city, user_coutry
    );

    if allowed_country.contains(&user_coutry.as_str()) {
        return Ok(ClientVpnConnectionHandlerResponse {
            allow: true,
            error_msg_on_failed_posture_compliance: Some(String::from("OK")),
            posture_compliance_statuses: vec![String::from("Unknown")],
            schema_version: Some(String::from("v2")),
        });
    } else {
        return Ok(ClientVpnConnectionHandlerResponse {
            allow: false,
            error_msg_on_failed_posture_compliance: Some(String::from(msg_deny)),
            posture_compliance_statuses: vec![String::from("Unknown")],
            schema_version: Some(String::from("v2")),
        });
    }
}
