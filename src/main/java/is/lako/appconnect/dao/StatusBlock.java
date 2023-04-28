package is.lako.appconnect.dao;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
public class StatusBlock {

    @JsonProperty(value = "code")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private int code;

    @JsonProperty(value = "event_code")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private EventCode eventCode;

    @JsonProperty(value = "message")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String message;

    @JsonProperty(value = "message_to_show")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String messageToShow;

    @JsonProperty(value = "errors")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<String> errors;

    @JsonProperty(value = "timestamp")
    private LocalDateTime timestamp;

    public StatusBlock(int code, String message, EventCode eventCode) {
        this.code = code;
        this.message = message;
        this.eventCode = eventCode;
        this.messageToShow = "Default message displayed on error";
        setTimestamp();
    }

    public StatusBlock(int code, String message) {
        this.code = code;
        this.message = message;
        this.messageToShow = "Default message displayed on error";
        setTimestamp();
    }

    public StatusBlock() {
    }

    public void setTimestamp() {
        this.timestamp = LocalDateTime.now();
    }

    public enum EventCode {
        EC_INACTIVE_ACCOUNT(4030),
        EC_UNAUTHORIZED(4010),
        EC_PROFILE_REFILLING(4061),
        EC_PROFILE_IS_NOT_FILLED(4062),
        EC_WRONG_INCOMING_FIELDS(4063),
        EC_WRONG_GOOD_ID(4041);

        private int code;

        private EventCode(int code) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }
    }
}