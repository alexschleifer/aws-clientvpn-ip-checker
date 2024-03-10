// This function requires the input described in:
// https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/connection-authorization.html

use lambda_runtime::{service_fn, tracing, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use serde_json;
use reqwest;


#[derive(Deserialize)]
struct Request {
    #[serde(rename = "connection-id")]
    connection_id: String,
    #[serde(rename = "endpoint-id")]
    endpoint_id: String,
    #[serde(rename = "common-name")]
    common_name: String,
    username: String,
    platform: String,
    #[serde(rename = "platform-version")]
    platform_version: String,
    #[serde(rename = "public-ip")]
    public_ip: String,
    #[serde(rename = "client-openvpn-version")]
    client_openvpn_version: String,
    groups: String,
    #[serde(rename = "schema-version")]
    schema_version: String,
}

#[derive(Serialize)]

struct Response {
    // message should be removed from responce json
    message: String,
    
    allow: bool,
    #[serde(rename = "error-msg-on-denied-connection")]
    error_msg_on_denied_connection: String,
    #[serde(rename = "posture-compliance-statuses")]
    posture_compliance_statuses : String,
    #[serde(rename = "schema-version")]
    schema_version: String, 
}

#[derive(Deserialize)]
struct IpInfoResponse{
    country: String,
    city: String,
    org: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // required to enable CloudWatch error logging by the runtime
    tracing::init_default_subscriber();

    let func = service_fn(my_handler);
    lambda_runtime::run(func).await?;
    Ok(())
}

pub(crate) async fn my_handler(_event: LambdaEvent<Request>) -> Result<Response, Error> {
    // extract some useful info from the request

    let allowed_country = ["IL","US","JP"]; // according to https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
    let user_coutry = String::new();
    let user_city = String::new();
    let _connection_id = _event.payload.connection_id;
    let _endpoint_id = _event.payload.endpoint_id;
    let _common_name = _event.payload.common_name;
    let _username = _event.payload.username;
    let _platform = _event.payload.platform;
    let _platform_version = _event.payload.platform_version;
    let _client_openvpn_version = _event.payload.client_openvpn_version;
    let _groups = _event.payload.groups;    
    let _schema_version = _event.payload.schema_version;
    let _ip_address = _event.payload.public_ip;
    let url = format!("https://ipinfo.io/{}",_ip_address);
    let check_ip_resp = match reqwest::get(&url).await {
        Ok(resp) => resp.text().await?,
        Err(e) => return Ok(Response { message: format!("Error fetching IP: {}", e), allow: false, error_msg_on_denied_connection: "".to_string(), posture_compliance_statuses: "".to_string(), schema_version: _schema_version }),
    };
    let check_ip_info: IpInfoResponse = match serde_json::from_str(&check_ip_resp) {
        Ok(info) => info,
        Err(e) => return Ok(Response { message: format!("Error fetching IP: {}", e), allow: false, error_msg_on_denied_connection: "".to_string(), posture_compliance_statuses: "".to_string(), schema_version: _schema_version }),
    };
 
    let user_coutry = check_ip_info.country;
    let user_city = check_ip_info.city;
    let user_org = check_ip_info.org;
    // prepare the response

    let msg_deny = format!("Connection from {}, {} is not allowed.", user_city, user_coutry);

    if allowed_country.contains(&user_coutry.as_str()) {
        return Ok(Response { message: check_ip_resp, allow: true, error_msg_on_denied_connection: "".to_string(), posture_compliance_statuses: "".to_string(), schema_version: _schema_version });
    }
    else {
        return Ok(Response { message: check_ip_resp,allow: false, error_msg_on_denied_connection: msg_deny, posture_compliance_statuses: "".to_string(), schema_version: _schema_version })
    }

    
}

#[cfg(test)]
mod tests {
    use crate::{my_handler, Request};
    use lambda_runtime::{Context, LambdaEvent};

    #[tokio::test]
    async fn response_is_good_for_simple_input() {
        let id = "ID";

        let mut context = Context::default();
        //context.public_ip = id.to_string();

        let payload = Request {
            connection_id: "Conn12232434".to_string(),
            endpoint_id: "alex-vpn-end-point".to_string(),
            common_name: "cert-alex-tyto".to_string(),
            username: "ale@tytocare.com".to_string(),
            platform: "win 7".to_string(),
            platform_version: "4.5.6.4".to_string(),
            public_ip: "46.210.45.213".to_string(),
            client_openvpn_version: "0pen-3.5.4".to_string(),
            groups: "group1234".to_string(),
            schema_version: "v2".to_string(),

        };
        let event = LambdaEvent { payload, context };

        let result = my_handler(event).await.expect("Expected Ok response");

        //assert_eq!(result.msg, "Command X executed.");
        //assert_eq!(result.req_id, id.to_string());
    }
}
