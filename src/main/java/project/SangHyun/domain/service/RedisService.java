package project.SangHyun.domain.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.Duration;

@Service
@Transactional
@RequiredArgsConstructor
public class RedisService {
    private final RedisTemplate redisTemplate;

    public String getData(String key){
        return (String) redisTemplate.opsForValue().get(key);
    }

    public void setDataWithExpiration(String key,String value,Long time){
        if (this.getData(key)!=null)
            this.deleteData(key);
        Duration expireDuration = Duration.ofSeconds(time);
        redisTemplate.opsForValue().set(key,value,expireDuration);
    }

    public void deleteData(String key) {
        redisTemplate.delete(key);
    }


}
