package project.SangHyun.web.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ReIssueRequestDto {
    String email;
    String refreshToken;
}
