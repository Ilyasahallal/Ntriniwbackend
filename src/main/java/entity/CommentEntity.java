package entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "comment")
public class CommentEntity {
    @Id
    private String id;

    private String userId;

    private String userFullname;

    private String content;

    private Instant createdAt;

    public void setCreatedAt(Instant now) {
    }
}
